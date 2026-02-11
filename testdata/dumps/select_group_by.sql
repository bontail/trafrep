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
-- Data for Name: sales; Type: TABLE DATA; Schema: public; Owner: -
--

SET SESSION AUTHORIZATION DEFAULT;

ALTER TABLE public.sales DISABLE TRIGGER ALL;

INSERT INTO public.sales (id, product, amount, region) VALUES (1, 'Widget', 100.00, 'North');
INSERT INTO public.sales (id, product, amount, region) VALUES (2, 'Gadget', 150.00, 'South');
INSERT INTO public.sales (id, product, amount, region) VALUES (3, 'Widget', 200.00, 'North');
INSERT INTO public.sales (id, product, amount, region) VALUES (4, 'Gadget', 175.00, 'South');


ALTER TABLE public.sales ENABLE TRIGGER ALL;

--
-- Name: sales_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.sales_id_seq', 4, true);


--
-- PostgreSQL database dump complete
--

