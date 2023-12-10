docker run -d --name mysql-auth-new -e MYSQL_ROOT_PASSWORD=admin -p 3306:3306 mysql:latest

SQL commands

```SQL
CREATE TABLE users (
    email varchar(255) PRIMARY KEY,
    password varchar(255),
    salt varchar(20) NOT NULL,
    created_at datetime default CURRENT_TIMESTAMP,
    updated_at datetime default CURRENT_TIMESTAMP
);

CREATE TABLE sessions (
    email varchar(255),
    is_active boolean NOT NULL,
    session_id varchar(40) NOT NULL,
    created_at datetime default CURRENT_TIMESTAMP,
    updated_at datetime default CURRENT_TIMESTAMP,
    FOREIGN KEY (email) REFERENCEs users(email)
)
```

CURL Requests

Signup User

curl -X POST http://localhost:4100/signup -H "Content-Type: application/json" -d '{"email": "user1@gmail.com", "password": "userpass"}'

curl -X POST http://localhost:4100/login -H "Content-Type: application/json" -d '{"email": "user1@gmail.com", "password": "userpass"}'

curl -X POST http://localhost:4100/validate-session -H "Content-Type: application/json" -d '{"sessionToken": "3a72f93ee2049d8fb20a"}'
