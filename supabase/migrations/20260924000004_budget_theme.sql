-- Per-budget appearance: Automatic (follow the device) / Light / Dark.
alter table oiko.budgets
  add column theme text not null default 'auto' check (theme in ('auto', 'light', 'dark'));
