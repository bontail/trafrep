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
-- Data for Name: transactions; Type: TABLE DATA; Schema: public; Owner: -
--

SET SESSION AUTHORIZATION DEFAULT;

ALTER TABLE public.transactions DISABLE TRIGGER ALL;

INSERT INTO public.transactions (id, amount, type) VALUES (1, 100.00, 'credit');
INSERT INTO public.transactions (id, amount, type) VALUES (2, -50.00, 'debit');
INSERT INTO public.transactions (id, amount, type) VALUES (3, 200.00, 'credit');
INSERT INTO public.transactions (id, amount, type) VALUES (4, -30.00, 'debit');


ALTER TABLE public.transactions ENABLE TRIGGER ALL;

--
-- Name: transactions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.transactions_id_seq', 4, true);


--
-- PostgreSQL database dump complete
--

