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
-- Data for Name: team_a; Type: TABLE DATA; Schema: public; Owner: -
--

SET SESSION AUTHORIZATION DEFAULT;

ALTER TABLE public.team_a DISABLE TRIGGER ALL;

INSERT INTO public.team_a (id, name) VALUES (1, 'Alice');
INSERT INTO public.team_a (id, name) VALUES (2, 'Bob');
INSERT INTO public.team_a (id, name) VALUES (3, 'Charlie');


ALTER TABLE public.team_a ENABLE TRIGGER ALL;

--
-- Data for Name: team_b; Type: TABLE DATA; Schema: public; Owner: -
--

ALTER TABLE public.team_b DISABLE TRIGGER ALL;

INSERT INTO public.team_b (id, name) VALUES (1, 'Bob');
INSERT INTO public.team_b (id, name) VALUES (2, 'David');
INSERT INTO public.team_b (id, name) VALUES (3, 'Eve');


ALTER TABLE public.team_b ENABLE TRIGGER ALL;

--
-- Name: team_a_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.team_a_id_seq', 3, true);


--
-- Name: team_b_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.team_b_id_seq', 3, true);


--
-- PostgreSQL database dump complete
--

