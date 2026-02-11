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
-- Data for Name: inventory; Type: TABLE DATA; Schema: public; Owner: -
--

SET SESSION AUTHORIZATION DEFAULT;

ALTER TABLE public.inventory DISABLE TRIGGER ALL;

INSERT INTO public.inventory (id, item, quantity, price) VALUES (1, 'Apple', 100, 0.50);
INSERT INTO public.inventory (id, item, quantity, price) VALUES (2, 'Banana', 150, 0.30);
INSERT INTO public.inventory (id, item, quantity, price) VALUES (3, 'Orange', 80, 0.60);


ALTER TABLE public.inventory ENABLE TRIGGER ALL;

--
-- Name: inventory_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.inventory_id_seq', 3, true);


--
-- PostgreSQL database dump complete
--

