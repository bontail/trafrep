--
-- PostgreSQL database dump
--


-- Dumped from database version 15.15
-- Dumped by pg_dump version 15.15

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Data for Name: customers; Type: TABLE DATA; Schema: public; Owner: -
--

SET SESSION AUTHORIZATION DEFAULT;

ALTER TABLE public.customers DISABLE TRIGGER ALL;

INSERT INTO public.customers (id, name, city) VALUES (1, 'Alice', 'NYC');
INSERT INTO public.customers (id, name, city) VALUES (2, 'Bob', 'LA');
INSERT INTO public.customers (id, name, city) VALUES (3, 'Charlie', 'NYC');


ALTER TABLE public.customers ENABLE TRIGGER ALL;

--
-- Data for Name: purchases; Type: TABLE DATA; Schema: public; Owner: -
--

ALTER TABLE public.purchases DISABLE TRIGGER ALL;

INSERT INTO public.purchases (id, customer_id, amount) VALUES (1, 1, 500.00);
INSERT INTO public.purchases (id, customer_id, amount) VALUES (2, 2, 300.00);
INSERT INTO public.purchases (id, customer_id, amount) VALUES (3, 1, 700.00);


ALTER TABLE public.purchases ENABLE TRIGGER ALL;

--
-- Name: customers_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.customers_id_seq', 3, true);


--
-- Name: purchases_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.purchases_id_seq', 3, true);


--
-- PostgreSQL database dump complete
--

