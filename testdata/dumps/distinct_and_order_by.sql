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
-- Data for Name: events; Type: TABLE DATA; Schema: public; Owner: -
--

SET SESSION AUTHORIZATION DEFAULT;

ALTER TABLE public.events DISABLE TRIGGER ALL;

INSERT INTO public.events (id, event_type, created_at) VALUES (1, 'login', '2024-01-01 09:00:00');
INSERT INTO public.events (id, event_type, created_at) VALUES (2, 'logout', '2024-01-01 09:30:00');
INSERT INTO public.events (id, event_type, created_at) VALUES (3, 'login', '2024-01-01 10:00:00');
INSERT INTO public.events (id, event_type, created_at) VALUES (4, 'error', '2024-01-01 10:15:00');


ALTER TABLE public.events ENABLE TRIGGER ALL;

--
-- Name: events_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.events_id_seq', 4, true);


--
-- PostgreSQL database dump complete
--

