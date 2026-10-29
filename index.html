-- HRIS schema for Supabase. Run once in: Supabase > SQL Editor.
-- Security model: every table has Row Level Security. The browser only holds the public
-- "anon" key; what a person can read or change is decided here, not in the web page.

create table profiles(id uuid primary key references auth.users on delete cascade,
  employee_id text unique, full_name text,
  role text not null default 'employee' check(role in('admin','manager','employee')));

create table employees(employee_id text primary key, full_name text not null, email text,
  designation text, start_date date not null, end_date date,
  status text not null default 'Active' check(status in('Active','Inactive')),
  manager_id text references employees(employee_id),
  check(end_date is null or end_date>=start_date));

create table attendance(employee_id text references employees on delete cascade, att_date date,
  code text not null check(code in('P','A','ANL','ANL/P','SL','SL/P','UPL','H','DO','OD','CL','ML','PTL','STL','SPL','EL')),
  updated_by uuid default auth.uid(), updated_at timestamptz default now(),
  primary key(employee_id,att_date));

create table contracts(id uuid primary key default gen_random_uuid(),
  employee_id text not null references employees on delete cascade,
  record_type text not null check(record_type in('Original Contract','Renewal','Amendment','Rehire')),
  contract_type text, start_date date not null, end_date date, date_signed date,
  verified boolean not null default false,
  approval_status text not null default 'Pending' check(approval_status in('Pending','Approved','Not Approved','Not Applicable')),
  notes text, created_by uuid default auth.uid(), created_at timestamptz default now(),
  check(end_date is null or end_date>=start_date));

-- Leave allowance is typed in by HR in Leave Tracker. Nothing is assumed.
create table leave_allowances(employee_id text references employees on delete cascade, year int,
  leave_code text check(leave_code in('ANL','ANL/P','SL','SL/P','UPL','CL','ML','PTL','STL','SPL','EL')),
  days numeric not null check(days>=0), primary key(employee_id,year,leave_code));

create table audit_log(id bigint generated always as identity primary key, at timestamptz default now(),
  actor uuid, action text, tbl text, row_data jsonb);

create function my_role() returns text language sql stable security definer set search_path=public as
$$ select role from profiles where id=auth.uid() $$;
create function my_emp() returns text language sql stable security definer set search_path=public as
$$ select employee_id from profiles where id=auth.uid() $$;
create function is_team(e text) returns boolean language sql stable security definer set search_path=public as
$$ select exists(select 1 from employees where employee_id=e and manager_id=my_emp()) $$;
create function can_see(e text) returns boolean language sql stable security definer set search_path=public as
$$ select my_role()='admin' or e=my_emp() or (my_role()='manager' and is_team(e)) $$;
create function can_edit(e text) returns boolean language sql stable security definer set search_path=public as
$$ select my_role()='admin' or (my_role()='manager' and is_team(e)) $$;

create function audit() returns trigger language plpgsql security definer set search_path=public as
$$ begin insert into audit_log(actor,action,tbl,row_data)
   values(auth.uid(),tg_op,tg_table_name,case when tg_op='DELETE' then to_jsonb(old) else to_jsonb(new) end);
   return null; end $$;

do $$ declare t text; begin
  foreach t in array array['profiles','employees','attendance','contracts','leave_allowances','audit_log'] loop
    execute format('alter table %I enable row level security',t);
  end loop;
  foreach t in array array['profiles','employees','attendance','contracts','leave_allowances'] loop
    execute format('create trigger %I after insert or update or delete on %I for each row execute function audit()','aud_'||t,t);
  end loop; end $$;

create policy p_sel on profiles for select using(id=auth.uid() or my_role()='admin');
create policy p_adm on profiles for all using(my_role()='admin') with check(my_role()='admin');
create policy e_sel on employees for select using(can_see(employee_id));
create policy e_adm on employees for all using(my_role()='admin') with check(my_role()='admin');
create policy a_sel on attendance for select using(can_see(employee_id));
create policy a_wr on attendance for all using(can_edit(employee_id)) with check(can_edit(employee_id));
create policy c_sel on contracts for select using(can_see(employee_id));
create policy c_adm on contracts for all using(my_role()='admin') with check(my_role()='admin');
create policy l_sel on leave_allowances for select using(can_see(employee_id));
create policy l_wr on leave_allowances for all using(can_edit(employee_id)) with check(can_edit(employee_id));
create policy audit_sel on audit_log for select using(my_role()='admin');
-- No insert/update/delete policy on audit_log: only the trigger can write, nobody can edit history.

-- FIRST ADMIN: create the user in Supabase > Authentication > Users, then run (with their UUID):
-- insert into profiles(id,employee_id,full_name,role) values('USER-UUID','E001','Your Name','admin');
-- (Add the matching row in employees first, or insert it via SQL, so the ID exists.)
