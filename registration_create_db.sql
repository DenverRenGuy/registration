CREATE DATABASE registration;

USE registration;

CREATE TABLE users(
	id INT NOT NULL AUTO_INCREMENT,
    first_name VARCHAR(55) NOT NULL,
    last_name VARCHAR(55) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (id)
);
