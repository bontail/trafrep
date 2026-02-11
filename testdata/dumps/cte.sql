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
-- Data for Name: categories; Type: TABLE DATA; Schema: public; Owner: -
--

SET SESSION AUTHORIZATION DEFAULT;

ALTER TABLE public.categories DISABLE TRIGGER ALL;

INSERT INTO public.categories (id, name, parent_id) VALUES (1, 'Electronics', NULL);
INSERT INTO public.categories (id, name, parent_id) VALUES (2, 'Laptops', 1);
INSERT INTO public.categories (id, name, parent_id) VALUES (3, 'Gaming Laptops', 2);


ALTER TABLE public.categories ENABLE TRIGGER ALL;

--
-- Name: categories_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.categories_id_seq', 3, true);


--
-- PostgreSQL database dump complete
--

