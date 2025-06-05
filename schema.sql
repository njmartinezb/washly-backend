/* 
We first of all need some way for a client to add
requests, so we need a user table, we'll hand roll basic password auth

1. User Table
2. Orders Table
3. Admins Table
4. Drivers Table
*/

CREATE TABLE users(
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  enabled boolean DEFAULT true,
  email TEXT NOT NULL,
  password TEXT NOT NULL,
  name TEXT NOT NULL,
  role TEXT NOT NULL
);

CREATE TABLE orders(
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMP DEFAULT now(),
  modified_at TIMESTAMP,
  full_address TEXT NOT NULL,
  location POINT NOT NULL,
  scheduled_for TIMESTAMP NOT NULL,
  status TEXT NOT NULL
);

CREATE TABLE reschedule_history(
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMP DEFAULT now(),
  order_id UUID REFERENCES orders(id),
  old_date TIMESTAMP NOT NULL,
  new_date TIMESTAMP NOT NULL
);
