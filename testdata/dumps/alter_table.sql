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
-- Data for Name: settings; Type: TABLE DATA; Schema: public; Owner: -
--

SET SESSION AUTHORIZATION DEFAULT;

ALTER TABLE public.settings DISABLE TRIGGER ALL;

INSERT INTO public.settings (id, key, setting_value) VALUES (2, 'lang', 'en');
INSERT INTO public.settings (id, key, setting_value) VALUES (1, 'theme', 'dark');


ALTER TABLE public.settings ENABLE TRIGGER ALL;

--
-- Name: settings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.settings_id_seq', 2, true);


--
-- PostgreSQL database dump complete
--

