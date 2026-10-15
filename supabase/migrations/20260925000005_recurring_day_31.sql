-- Recurring items may fall on any day 1-31; months that are shorter use their last day (handled in the app).
alter table oiko.recurring drop constraint recurring_day_check;
alter table oiko.recurring add constraint recurring_day_check check (day between 1 and 31);
