provider text not null check (provider in ('iyzico')),
  submerchant_key text not null,
  onboarding_status text not null default 'pending' check (onboarding_status in ('pending','approved','rejected')),
  updated_at timestamptz not null default now()
);

create table if not exists public.payment_events (
  id uuid primary key default gen_random_uuid(),
  provider text not null,
  provider_event_id text not null,
  order_id uuid references public.orders(id) on delete set null,
  event_type text not null,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique(provider, provider_event_id)
);

alter table public.profiles enable row level security;
alter table public.seller_profiles enable row level security;
alter table public.products enable row level security;
alter table public.orders enable row level security;
alter table public.order_items enable row level security;
alter table public.platform_settings enable row level security;
alter table public.seller_payment_accounts enable row level security;
alter table public.payment_events enable row level security;

-- Profiles: users can read their own profile; no client role can elevate role.
create policy "profile read own or admin" on public.profiles for select to authenticated
using (id = auth.uid() or public.is_admin());
revoke update on public.profiles from authenticated;
grant update (full_name) on public.profiles to authenticated;
create policy "profile update own name" on public.profiles for update to authenticated
using (id = auth.uid()) with check (id = auth.uid());

-- Sellers can create only their own pending application. Admin approval is server/admin-only.
create policy "seller read own or admin" on public.seller_profiles for select to authenticated
using (user_id = auth.uid() or public.is_admin());
create policy "public read approved seller stores" on public.seller_profiles for select to anon, authenticated
using (status = 'approved');
create policy "seller apply own pending" on public.seller_profiles for insert to authenticated
with check (user_id = auth.uid() and status = 'pending');
create policy "seller admin update" on public.seller_profiles for update to authenticated
using (public.is_admin()) with check (public.is_admin());

-- Public product reads are limited to active products from approved sellers.
create policy "public read approved products" on public.products for select to anon, authenticated
using (
  (is_active = true and exists (select 1 from public.seller_profiles s where s.user_id = seller_id and s.status = 'approved'))
  or seller_id = auth.uid() or public.is_admin()
);
create policy "approved seller insert own product" on public.products for insert to authenticated
with check (seller_id = auth.uid() and exists (select 1 from public.seller_profiles s where s.user_id = auth.uid() and s.status = 'approved'));
create policy "seller update own product" on public.products for update to authenticated
using (seller_id = auth.uid() and exists (select 1 from public.seller_profiles s where s.user_id = auth.uid() and s.status = 'approved'))
with check (seller_id = auth.uid() and exists (select 1 from public.seller_profiles s where s.user_id = auth.uid() and s.status = 'approved'));
create policy "seller delete own product" on public.products for delete to authenticated
using (seller_id = auth.uid() and exists (select 1 from public.seller_profiles s where s.user_id = auth.uid() and s.status = 'approved'));

-- SECURITY DEFINER helpers avoid recursive RLS checks between orders and order_items.
create or replace function public.is_order_buyer(p_order_id uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.orders o where o.id = p_order_id and o.buyer_id = auth.uid());
$$;
create or replace function public.is_order_seller(p_order_id uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.order_items i where i.order_id = p_order_id and i.seller_id = auth.uid());
$$;
revoke all on function public.is_order_buyer(uuid) from public;
revoke all on function public.is_order_seller(uuid) from public;
grant execute on function public.is_order_buyer(uuid), public.is_order_seller(uuid) to authenticated;

-- Orders are created only through the RPC below. Buyers and involved sellers can read.
create policy "buyer or seller reads orders" on public.orders for select to authenticated
using (public.is_order_buyer(id) or public.is_order_seller(id) or public.is_admin());
create policy "buyer or seller reads order items" on public.order_items for select to authenticated
using (public.is_order_buyer(order_id) or seller_id = auth.uid() or public.is_admin());

-- Do not expose settings/provider secrets or payment event payloads to clients.
revoke all on public.platform_settings from anon, authenticated;
revoke all on public.seller_payment_accounts from anon, authenticated;
revoke all on public.payment_events from anon, authenticated;
revoke insert, update, delete on public.orders from anon, authenticated;
revoke insert, update, delete on public.order_items from anon, authenticated;
grant select on public.products to anon, authenticated;
grant insert, update, delete on public.products to authenticated;
grant select on public.orders, public.order_items to authenticated;
grant select, insert on public.seller_profiles to anon, authenticated;
grant update on public.seller_profiles to authenticated;
grant select on public.profiles to authenticated;

-- Safe public projection: never returns seller personal/payment details.
create or replace view public.products_public as
select p.id, p.title, p.description, p.category, p.price, p.stock, p.image_url,
       p.created_at, s.store_name
from public.products p
join public.seller_profiles s on s.user_id = p.seller_id
where p.is_active = true and p.stock >= 0 and s.status = 'approved';
grant select on public.products_public to anon, authenticated;

-- Server-validated pending order creation. Client supplies product IDs and quantities only.
create or replace function public.create_pending_order(p_items jsonb)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_order_id uuid;
  v_buyer uuid := auth.uid();
  v_rate numeric(5,4);
  v_total numeric(12,2) := 0;
  v_commission numeric(12,2) := 0;
  v_seller_total numeric(12,2) := 0;
  v_item record;
  v_product public.products%rowtype;
  v_qty integer;
  v_line numeric(12,2);
  v_fee numeric(12,2);
  v_payout numeric(12,2);
begin
  if v_buyer is null then raise exception 'Giriş yapmalısınız.'; end if;
  if jsonb_typeof(p_items) <> 'array' or jsonb_array_length(p_items) = 0 or jsonb_array_length(p_items) > 30 then
    raise exception 'Sepet geçersiz.';
  end if;
  select commission_rate into v_rate from public.platform_settings where id = true;
  if v_rate is null then raise exception 'Platform komisyon ayarı bulunamadı.'; end if;

  -- Validate and price each line from database, never from browser-supplied prices.
  for v_item in select value from jsonb_array_elements(p_items) loop
    if coalesce(v_item.value->>'product_id','') = '' then raise exception 'Ürün bilgisi eksik.'; end if;
    v_qty := (v_item.value->>'quantity')::integer;
    if v_qty < 1 or v_qty > 20 then raise exception 'Ürün adedi geçersiz.'; end if;
    select * into v_product from public.products p
    where p.id = (v_item.value->>'product_id')::uuid and p.is_active = true
    for update;
    if not found then raise exception 'Ürün bulunamadı veya satışta değil.'; end if;
    if v_product.stock < v_qty then raise exception 'Yetersiz stok: %', v_product.title; end if;
    if not exists (select 1 from public.seller_profiles s where s.user_id = v_product.seller_id and s.status = 'approved') then
      raise exception 'Satıcı mağazası aktif değil.';
    end if;
    v_line := round(v_product.price * v_qty, 2);
    v_fee := round(v_line * v_rate, 2);
    v_payout := v_line - v_fee;
    v_total := v_total + v_line;
    v_commission := v_commission + v_fee;
    v_seller_total := v_seller_total + v_payout;
  end loop;

  insert into public.orders (buyer_id,total_amount,commission_amount,seller_payout_amount)
  values (v_buyer,v_total,v_commission,v_seller_total) returning id into v_order_id;

  for v_item in select value from jsonb_array_elements(p_items) loop
    v_qty := (v_item.value->>'quantity')::integer;
    select * into v_product from public.products p where p.id = (v_item.value->>'product_id')::uuid;
    v_line := round(v_product.price * v_qty, 2);
    v_fee := round(v_line * v_rate, 2);
    v_payout := v_line - v_fee;
    update public.products set stock = stock - v_qty, updated_at = now()
    where id = v_product.id and stock >= v_qty;
    if not found then raise exception 'Stok sipariş sırasında değişti: %', v_product.title; end if;
