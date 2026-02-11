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
-- Data for Name: log_summary; Type: TABLE DATA; Schema: public; Owner: -
--

SET SESSION AUTHORIZATION DEFAULT;

ALTER TABLE public.log_summary DISABLE TRIGGER ALL;

INSERT INTO public.log_summary (date, total_count, error_count) VALUES ('2024-01-01', 3, 1);


ALTER TABLE public.log_summary ENABLE TRIGGER ALL;

--
-- Data for Name: logs; Type: TABLE DATA; Schema: public; Owner: -
--

ALTER TABLE public.logs DISABLE TRIGGER ALL;

INSERT INTO public.logs (id, message, level, created_at) VALUES (1, 'App started', 'INFO', '2024-01-01 08:00:00');
INSERT INTO public.logs (id, message, level, created_at) VALUES (2, 'Error occurred', 'ERROR', '2024-01-01 08:05:00');
INSERT INTO public.logs (id, message, level, created_at) VALUES (3, 'Warning issued', 'WARN', '2024-01-01 08:10:00');


ALTER TABLE public.logs ENABLE TRIGGER ALL;

--
-- Name: logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.logs_id_seq', 3, true);


--
-- PostgreSQL database dump complete
--

