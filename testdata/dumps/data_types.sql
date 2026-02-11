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
-- Data for Name: data_types; Type: TABLE DATA; Schema: public; Owner: -
--

SET SESSION AUTHORIZATION DEFAULT;

ALTER TABLE public.data_types DISABLE TRIGGER ALL;

INSERT INTO public.data_types (id, text_col, int_col, bool_col, date_col, timestamp_col, json_col, array_col) VALUES (1, 'test', 42, true, '2024-01-01', '2024-01-01 12:00:00', '{"key": "value"}', '{1,2,3}');


ALTER TABLE public.data_types ENABLE TRIGGER ALL;

--
-- Name: data_types_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.data_types_id_seq', 1, true);


--
-- PostgreSQL database dump complete
--

