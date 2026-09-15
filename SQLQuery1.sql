use LoginSystem;

CREATE TABLE Users (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    Email NVARCHAR(255) NOT NULL UNIQUE,
    PasswordHash NVARCHAR(255) NOT NULL
);

alter table Users
add IsVerified bit not null default 0;

select * from Users;

delete from Users where Id = 6;

alter table Users
alter column PasswordHash NVARCHAR(255) NULL;


alter table Users
add GoogleSub NVARCHAR(255) NULL;


CREATE UNIQUE INDEX UX_Users_GoogleSub
ON Users(GoogleSub)
WHERE GoogleSub IS NOT NULL;