create table if not exists users(id text primary key,sub text unique not null,email text,name text,picture text,created integer);
create table if not exists sessions(h text primary key,uid text not null,exp integer not null);
create table if not exists teams(id text primary key,name text not null,created integer);
create table if not exists members(team_id text not null,uid text not null,role text not null,primary key(team_id,uid));
create table if not exists invites(code text primary key,team_id text not null,exp integer not null,by text);
create table if not exists boards(id text primary key,owner text not null,team_id text,name text not null,seq integer not null default 0);
create table if not exists items(board_id text not null,id text not null,k text not null,d text not null,u integer not null,gone integer not null default 0,s integer not null,primary key(board_id,id));
create index if not exists items_s on items(board_id,s);
