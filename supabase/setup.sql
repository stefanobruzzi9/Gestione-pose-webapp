-- =====================================================================
--  Gestione Pose · database condiviso con utenti e permessi (Supabase)
--
--  Dove si esegue: Supabase → SQL Editor → New query → incolla → Run.
--  Si può rieseguire quando serve: non cancella i dati.
--
--  PRIMA di eseguirlo:
--   1. crea gli utenti in Authentication → Users → Add user →
--      Create new user (spunta «Auto Confirm User»);
--   2. sostituisci le due email nel punto 6, in fondo.
--
--  Ruoli:
--   admin    → vede e modifica tutto, approva o rifiuta le proposte
--   lettura  → vede tutto; le sue modifiche diventano proposte che
--              l'amministratore deve approvare
-- =====================================================================

-- 1) Dati dell'app: una sola riga con tutto il database dell'app
create table if not exists public.app_state (
  id int primary key,
  data jsonb,
  updated_at timestamptz default now()
);
insert into public.app_state (id, data) values (1, '{}') on conflict (id) do nothing;

-- 2) Utenti che possono entrare, con nome e ruolo
create table if not exists public.utenti (
  id uuid primary key references auth.users(id) on delete cascade,
  nome text not null,
  ruolo text not null check (ruolo in ('admin', 'lettura'))
);

-- 3) Proposte di modifica in attesa di approvazione
create table if not exists public.proposte (
  id bigint generated always as identity primary key,
  creata_il timestamptz not null default now(),
  autore uuid not null default auth.uid(),
  autore_nome text,
  descrizione text,
  modifiche jsonb not null,
  stato text not null default 'in_attesa' check (stato in ('in_attesa', 'approvata', 'rifiutata')),
  deciso_il timestamptz,
  deciso_da uuid,
  nota text
);

-- 4) Ruolo di chi sta usando l'app (null = non abilitato)
create or replace function public.mio_ruolo() returns text
language sql stable security definer set search_path = public
as $$ select ruolo from public.utenti where id = auth.uid() $$;
revoke all on function public.mio_ruolo() from public, anon;
grant execute on function public.mio_ruolo() to authenticated;

-- autore, data e stato delle proposte li scrive il database, non l'app
create or replace function public.proposte_controlla() returns trigger
language plpgsql set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    new.autore := auth.uid();
    new.autore_nome := (select nome from public.utenti where id = auth.uid());
    new.stato := 'in_attesa';
    new.creata_il := now();
    new.deciso_il := null;
    new.deciso_da := null;
  elsif new.stato is distinct from old.stato then
    new.deciso_il := now();
    new.deciso_da := auth.uid();
  end if;
  return new;
end $$;
drop trigger if exists proposte_controlla on public.proposte;
create trigger proposte_controlla before insert or update on public.proposte
  for each row execute function public.proposte_controlla();

-- 5) Permessi: senza accesso non si vede niente
alter table public.app_state enable row level security;
alter table public.utenti enable row level security;
alter table public.proposte enable row level security;

revoke all on public.app_state, public.utenti, public.proposte from anon, authenticated;
grant select, insert, update on public.app_state to authenticated;
grant select on public.utenti to authenticated;
grant select, insert, update on public.proposte to authenticated;

drop policy if exists app_state_lettura on public.app_state;
create policy app_state_lettura on public.app_state for select to authenticated
  using (public.mio_ruolo() is not null);
drop policy if exists app_state_inserimento on public.app_state;
create policy app_state_inserimento on public.app_state for insert to authenticated
  with check (public.mio_ruolo() = 'admin');
drop policy if exists app_state_modifica on public.app_state;
create policy app_state_modifica on public.app_state for update to authenticated
  using (public.mio_ruolo() = 'admin') with check (public.mio_ruolo() = 'admin');

drop policy if exists utenti_lettura on public.utenti;
create policy utenti_lettura on public.utenti for select to authenticated
  using (id = auth.uid() or public.mio_ruolo() = 'admin');

drop policy if exists proposte_lettura on public.proposte;
create policy proposte_lettura on public.proposte for select to authenticated
  using (autore = auth.uid() or public.mio_ruolo() = 'admin');
drop policy if exists proposte_inserimento on public.proposte;
create policy proposte_inserimento on public.proposte for insert to authenticated
  with check (public.mio_ruolo() is not null);
drop policy if exists proposte_decisione on public.proposte;
create policy proposte_decisione on public.proposte for update to authenticated
  using (public.mio_ruolo() = 'admin') with check (public.mio_ruolo() = 'admin');

-- 6) Chi può entrare e con quale ruolo  ←  SOSTITUISCI LE DUE EMAIL
insert into public.utenti (id, nome, ruolo)
select id, 'Stefano', 'admin' from auth.users where lower(email) = lower('EMAIL-DI-STEFANO')
on conflict (id) do update set nome = excluded.nome, ruolo = excluded.ruolo;

insert into public.utenti (id, nome, ruolo)
select id, 'Amministrazione', 'lettura' from auth.users where lower(email) = lower('EMAIL-AMMINISTRAZIONE')
on conflict (id) do update set nome = excluded.nome, ruolo = excluded.ruolo;

-- Controllo finale: devono comparire i due utenti con il loro ruolo
select u.nome, u.ruolo, a.email from public.utenti u join auth.users a on a.id = u.id order by u.ruolo;
