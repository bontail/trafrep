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
-- Data for Name: documents; Type: TABLE DATA; Schema: public; Owner: -
--

SET SESSION AUTHORIZATION DEFAULT;

ALTER TABLE public.documents DISABLE TRIGGER ALL;

INSERT INTO public.documents (id, filename, content) VALUES (1, 'report_2024.pdf', 'Annual report');
INSERT INTO public.documents (id, filename, content) VALUES (2, 'notes.txt', 'Meeting notes');
INSERT INTO public.documents (id, filename, content) VALUES (3, 'report_2023.pdf', 'Previous report');


ALTER TABLE public.documents ENABLE TRIGGER ALL;

--
-- Name: documents_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.documents_id_seq', 3, true);


--
-- PostgreSQL database dump complete
--

