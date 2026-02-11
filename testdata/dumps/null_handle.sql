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
-- Data for Name: contacts; Type: TABLE DATA; Schema: public; Owner: -
--

SET SESSION AUTHORIZATION DEFAULT;

ALTER TABLE public.contacts DISABLE TRIGGER ALL;

INSERT INTO public.contacts (id, name, phone, email) VALUES (1, 'Alice', '123-456', 'alice@test.com');
INSERT INTO public.contacts (id, name, phone, email) VALUES (2, 'Bob', NULL, 'bob@test.com');
INSERT INTO public.contacts (id, name, phone, email) VALUES (3, 'Charlie', '789-012', NULL);


ALTER TABLE public.contacts ENABLE TRIGGER ALL;

--
-- Name: contacts_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.contacts_id_seq', 3, true);


--
-- PostgreSQL database dump complete
--

