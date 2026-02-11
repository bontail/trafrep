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
-- Data for Name: posts; Type: TABLE DATA; Schema: public; Owner: -
--

SET SESSION AUTHORIZATION DEFAULT;

ALTER TABLE public.posts DISABLE TRIGGER ALL;

INSERT INTO public.posts (id, title, content) VALUES (1, 'Post 1', 'Content 1');
INSERT INTO public.posts (id, title, content) VALUES (2, 'Post 2', 'Content 2');
INSERT INTO public.posts (id, title, content) VALUES (3, 'Post 3', 'Content 3');
INSERT INTO public.posts (id, title, content) VALUES (4, 'Post 4', 'Content 4');
INSERT INTO public.posts (id, title, content) VALUES (5, 'Post 5', 'Content 5');
INSERT INTO public.posts (id, title, content) VALUES (6, 'Post 6', 'Content 6');
INSERT INTO public.posts (id, title, content) VALUES (7, 'Post 7', 'Content 7');
INSERT INTO public.posts (id, title, content) VALUES (8, 'Post 8', 'Content 8');
INSERT INTO public.posts (id, title, content) VALUES (9, 'Post 9', 'Content 9');
INSERT INTO public.posts (id, title, content) VALUES (10, 'Post 10', 'Content 10');
INSERT INTO public.posts (id, title, content) VALUES (11, 'Post 11', 'Content 11');
INSERT INTO public.posts (id, title, content) VALUES (12, 'Post 12', 'Content 12');
INSERT INTO public.posts (id, title, content) VALUES (13, 'Post 13', 'Content 13');
INSERT INTO public.posts (id, title, content) VALUES (14, 'Post 14', 'Content 14');
INSERT INTO public.posts (id, title, content) VALUES (15, 'Post 15', 'Content 15');
INSERT INTO public.posts (id, title, content) VALUES (16, 'Post 16', 'Content 16');
INSERT INTO public.posts (id, title, content) VALUES (17, 'Post 17', 'Content 17');
INSERT INTO public.posts (id, title, content) VALUES (18, 'Post 18', 'Content 18');
INSERT INTO public.posts (id, title, content) VALUES (19, 'Post 19', 'Content 19');
INSERT INTO public.posts (id, title, content) VALUES (20, 'Post 20', 'Content 20');
INSERT INTO public.posts (id, title, content) VALUES (21, 'Post 21', 'Content 21');
INSERT INTO public.posts (id, title, content) VALUES (22, 'Post 22', 'Content 22');
INSERT INTO public.posts (id, title, content) VALUES (23, 'Post 23', 'Content 23');
INSERT INTO public.posts (id, title, content) VALUES (24, 'Post 24', 'Content 24');
INSERT INTO public.posts (id, title, content) VALUES (25, 'Post 25', 'Content 25');
INSERT INTO public.posts (id, title, content) VALUES (26, 'Post 26', 'Content 26');
INSERT INTO public.posts (id, title, content) VALUES (27, 'Post 27', 'Content 27');
INSERT INTO public.posts (id, title, content) VALUES (28, 'Post 28', 'Content 28');
INSERT INTO public.posts (id, title, content) VALUES (29, 'Post 29', 'Content 29');
INSERT INTO public.posts (id, title, content) VALUES (30, 'Post 30', 'Content 30');
INSERT INTO public.posts (id, title, content) VALUES (31, 'Post 31', 'Content 31');
INSERT INTO public.posts (id, title, content) VALUES (32, 'Post 32', 'Content 32');
INSERT INTO public.posts (id, title, content) VALUES (33, 'Post 33', 'Content 33');
INSERT INTO public.posts (id, title, content) VALUES (34, 'Post 34', 'Content 34');
INSERT INTO public.posts (id, title, content) VALUES (35, 'Post 35', 'Content 35');
INSERT INTO public.posts (id, title, content) VALUES (36, 'Post 36', 'Content 36');
INSERT INTO public.posts (id, title, content) VALUES (37, 'Post 37', 'Content 37');
INSERT INTO public.posts (id, title, content) VALUES (38, 'Post 38', 'Content 38');
INSERT INTO public.posts (id, title, content) VALUES (39, 'Post 39', 'Content 39');
INSERT INTO public.posts (id, title, content) VALUES (40, 'Post 40', 'Content 40');
INSERT INTO public.posts (id, title, content) VALUES (41, 'Post 41', 'Content 41');
INSERT INTO public.posts (id, title, content) VALUES (42, 'Post 42', 'Content 42');
INSERT INTO public.posts (id, title, content) VALUES (43, 'Post 43', 'Content 43');
INSERT INTO public.posts (id, title, content) VALUES (44, 'Post 44', 'Content 44');
INSERT INTO public.posts (id, title, content) VALUES (45, 'Post 45', 'Content 45');
INSERT INTO public.posts (id, title, content) VALUES (46, 'Post 46', 'Content 46');
INSERT INTO public.posts (id, title, content) VALUES (47, 'Post 47', 'Content 47');
INSERT INTO public.posts (id, title, content) VALUES (48, 'Post 48', 'Content 48');
INSERT INTO public.posts (id, title, content) VALUES (49, 'Post 49', 'Content 49');
INSERT INTO public.posts (id, title, content) VALUES (50, 'Post 50', 'Content 50');


ALTER TABLE public.posts ENABLE TRIGGER ALL;

--
-- Name: posts_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.posts_id_seq', 50, true);


--
-- PostgreSQL database dump complete
--

