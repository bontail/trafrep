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
-- Data for Name: departments; Type: TABLE DATA; Schema: public; Owner: -
--

SET SESSION AUTHORIZATION DEFAULT;

ALTER TABLE public.departments DISABLE TRIGGER ALL;

INSERT INTO public.departments (id, name) VALUES (1, 'IT');
INSERT INTO public.departments (id, name) VALUES (2, 'HR');
INSERT INTO public.departments (id, name) VALUES (3, 'Sales');


ALTER TABLE public.departments ENABLE TRIGGER ALL;

--
-- Data for Name: employees; Type: TABLE DATA; Schema: public; Owner: -
--

ALTER TABLE public.employees DISABLE TRIGGER ALL;

INSERT INTO public.employees (id, name, dept_id) VALUES (1, 'John', 1);
INSERT INTO public.employees (id, name, dept_id) VALUES (2, 'Jane', 2);
INSERT INTO public.employees (id, name, dept_id) VALUES (3, 'Mike', 1);


ALTER TABLE public.employees ENABLE TRIGGER ALL;

--
-- Name: departments_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.departments_id_seq', 3, true);


--
-- Name: employees_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.employees_id_seq', 3, true);


--
-- PostgreSQL database dump complete
--

