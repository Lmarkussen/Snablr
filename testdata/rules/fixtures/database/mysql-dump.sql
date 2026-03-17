-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int NOT NULL,
  `username` varchar(64) NOT NULL
);
LOCK TABLES `users` WRITE;
INSERT INTO `users` VALUES (1,'alice');
INSERT INTO `users` VALUES (2,'bob');
UNLOCK TABLES;
