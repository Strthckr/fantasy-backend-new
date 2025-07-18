-- MySQL dump 10.13  Distrib 8.0.40, for Win64 (x86_64)
--
-- Host: localhost    Database: fantasy_app
-- ------------------------------------------------------
-- Server version	8.0.40

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `contests`
--

DROP TABLE IF EXISTS `contests`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `contests` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `contest_name` varchar(100) DEFAULT NULL,
  `entry_fee` decimal(10,2) DEFAULT NULL,
  `prize_pool` decimal(10,2) DEFAULT '0.00',
  `start_time` datetime DEFAULT NULL,
  `end_time` datetime DEFAULT NULL,
  `status` varchar(50) NOT NULL DEFAULT 'active',
  `match_id` int DEFAULT NULL,
  `max_teams_per_user` int DEFAULT '1',
  `commission_percentage` int DEFAULT '15',
  PRIMARY KEY (`id`),
  KEY `match_id` (`match_id`),
  CONSTRAINT `contests_ibfk_1` FOREIGN KEY (`match_id`) REFERENCES `matches` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `contests`
--

LOCK TABLES `contests` WRITE;
/*!40000 ALTER TABLE `contests` DISABLE KEYS */;
INSERT INTO `contests` VALUES (8,'','Super Smash',99.99,0.00,'2025-06-26 11:45:35','2025-06-26 13:45:35','active',NULL,1,15),(10,'Weekend Match',NULL,50.00,5000.00,'2025-06-25 13:00:00','2025-06-25 15:00:00','active',NULL,1,15),(11,'Boom Boom',NULL,50.00,5000.00,'2025-06-27 17:10:23','2025-06-25 15:00:00','prizes_distributed',1,3,15),(12,'Lovely Contest',NULL,50.00,5000.00,'2025-06-25 13:00:00','2025-06-25 15:00:00','active',NULL,0,15),(13,'Checked Contest',NULL,50.00,5000.00,'2025-06-25 13:00:00','2025-06-25 15:00:00','active',1,1,15),(14,'Super Contest',NULL,100.00,5000.00,'2025-07-01 15:00:00','2025-07-01 17:00:00','active',2,5,20);
/*!40000 ALTER TABLE `contests` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `entries`
--

DROP TABLE IF EXISTS `entries`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `entries` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int DEFAULT NULL,
  `team_id` int DEFAULT NULL,
  `contest_id` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `team_id` (`team_id`),
  KEY `contest_id` (`contest_id`),
  CONSTRAINT `entries_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  CONSTRAINT `entries_ibfk_2` FOREIGN KEY (`team_id`) REFERENCES `teams` (`id`),
  CONSTRAINT `entries_ibfk_3` FOREIGN KEY (`contest_id`) REFERENCES `contests` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=27 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `entries`
--

LOCK TABLES `entries` WRITE;
/*!40000 ALTER TABLE `entries` DISABLE KEYS */;
INSERT INTO `entries` VALUES (10,3,3,8),(11,3,3,8),(12,3,3,8),(13,3,3,8),(14,4,3,8),(15,4,3,8),(16,4,3,8),(17,4,3,8),(18,4,3,8),(19,4,3,8),(20,4,3,8),(21,6,3,11),(22,6,3,11),(23,6,3,11),(24,7,3,11),(25,7,3,11),(26,7,27,13);
/*!40000 ALTER TABLE `entries` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `matches`
--

DROP TABLE IF EXISTS `matches`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `matches` (
  `id` int NOT NULL AUTO_INCREMENT,
  `match_name` varchar(100) NOT NULL,
  `start_time` datetime NOT NULL,
  `end_time` datetime NOT NULL,
  `status` enum('upcoming','live','completed') DEFAULT 'upcoming',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `matches`
--

LOCK TABLES `matches` WRITE;
/*!40000 ALTER TABLE `matches` DISABLE KEYS */;
INSERT INTO `matches` VALUES (1,'India vs Australia','2025-06-30 11:38:10','2025-06-27 17:27:55','upcoming'),(2,'England vs Pakistan','2025-06-27 18:27:55','2025-06-27 20:27:55','completed');
/*!40000 ALTER TABLE `matches` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `notifications`
--

DROP TABLE IF EXISTS `notifications`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `notifications` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `message` text NOT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `notifications_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `notifications`
--

LOCK TABLES `notifications` WRITE;
/*!40000 ALTER TABLE `notifications` DISABLE KEYS */;
INSERT INTO `notifications` VALUES (1,7,'Γé╣500.00 added to your wallet successfully.','2025-06-29 18:20:57');
/*!40000 ALTER TABLE `notifications` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `platform_earnings`
--

DROP TABLE IF EXISTS `platform_earnings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `platform_earnings` (
  `id` int NOT NULL AUTO_INCREMENT,
  `contest_id` int DEFAULT NULL,
  `commission_amount` decimal(10,2) DEFAULT NULL,
  `collected_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `platform_earnings`
--

LOCK TABLES `platform_earnings` WRITE;
/*!40000 ALTER TABLE `platform_earnings` DISABLE KEYS */;
/*!40000 ALTER TABLE `platform_earnings` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `prize_distributions`
--

DROP TABLE IF EXISTS `prize_distributions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `prize_distributions` (
  `id` int NOT NULL AUTO_INCREMENT,
  `contest_id` int NOT NULL,
  `rank_position` int NOT NULL,
  `percentage` decimal(5,2) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `contest_id` (`contest_id`),
  CONSTRAINT `prize_distributions_ibfk_1` FOREIGN KEY (`contest_id`) REFERENCES `contests` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `prize_distributions`
--

LOCK TABLES `prize_distributions` WRITE;
/*!40000 ALTER TABLE `prize_distributions` DISABLE KEYS */;
INSERT INTO `prize_distributions` VALUES (4,8,1,50.00),(5,8,2,30.00),(6,8,3,20.00),(7,11,1,50.00),(8,11,2,30.00),(9,11,3,20.00),(10,13,1,70.00),(11,13,2,20.00),(12,13,3,10.00);
/*!40000 ALTER TABLE `prize_distributions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `scores`
--

DROP TABLE IF EXISTS `scores`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `scores` (
  `id` int NOT NULL AUTO_INCREMENT,
  `entry_id` int DEFAULT NULL,
  `points` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `entry_id` (`entry_id`),
  CONSTRAINT `scores_ibfk_1` FOREIGN KEY (`entry_id`) REFERENCES `entries` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `scores`
--

LOCK TABLES `scores` WRITE;
/*!40000 ALTER TABLE `scores` DISABLE KEYS */;
INSERT INTO `scores` VALUES (6,10,50),(7,11,60),(8,12,40),(9,13,30);
/*!40000 ALTER TABLE `scores` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `teams`
--

DROP TABLE IF EXISTS `teams`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `teams` (
  `id` int NOT NULL AUTO_INCREMENT,
  `team_name` varchar(100) NOT NULL,
  `players` text NOT NULL,
  `user_id` int DEFAULT NULL,
  `total_points` int DEFAULT '0',
  `contest_id` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_user` (`user_id`),
  CONSTRAINT `fk_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=34 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `teams`
--

LOCK TABLES `teams` WRITE;
/*!40000 ALTER TABLE `teams` DISABLE KEYS */;
INSERT INTO `teams` VALUES (3,'The Yorkers','[\"Hardik Pandya\", \"KL Rahul\", \"Shubman Gill\", \"Jadeja\"]',NULL,0,0),(4,'MyTeam','[\"Player1\", \"Player2\", \"Player3\"]',7,0,11),(5,'FreshTeam','[\"Player1\", \"Player2\", \"Player3\"]',7,0,11),(6,'Happy Team','[\"Player1\", \"Player2\", \"Player3\"]',7,0,11),(7,'Happy Team','[\"Player1\", \"Player2\", \"Player3\"]',7,0,11),(8,'Good Team','[\"Player1\", \"Player2\", \"Player3\"]',7,0,11),(9,'Bad Team','[\"Player1\", \"Player2\", \"Player3\"]',7,0,11),(10,'Goods Team','[\"Player1\", \"Player2\", \"Player3\"]',7,0,12),(11,'Goods Team','[\"Player1\", \"Player2\", \"Player3\"]',7,0,12),(12,'Goods Team','[\"Player1\", \"Player2\", \"Player3\"]',7,0,12),(13,'Goods Team','[\"Player1\", \"Player2\", \"Player3\"]',7,0,12),(14,'Goods Team','[\"Player1\", \"Player2\", \"Player3\"]',7,0,12),(15,'Goods Team','[\"Player1\", \"Player2\", \"Player3\"]',7,0,12),(16,'Goods Team','[\"Player1\", \"Player2\", \"Player3\"]',7,0,12),(17,'Goods Team','[\"Player1\", \"Player2\", \"Player3\"]',7,0,12),(18,'Goods Team','[\"Player1\", \"Player2\", \"Player3\"]',7,0,12),(19,'Goods Team','[\"Player1\", \"Player2\", \"Player3\"]',7,0,12),(20,'Goods Team','[\"Player1\", \"Player2\", \"Player3\"]',7,0,12),(21,'Goods Team','[\"Player1\", \"Player2\", \"Player3\"]',7,0,12),(22,'Goods Team','[\"Player1\", \"Player2\", \"Player3\"]',7,0,12),(23,'Goods Team','[\"Player1\", \"Player2\", \"Player3\"]',7,0,12),(24,'Goods Team','[\"Player1\", \"Player2\", \"Player3\"]',7,0,12),(25,'Goods Team','[\"Player1\", \"Player2\", \"Player3\"]',7,0,12),(26,'Goods Team','[\"Player1\", \"Player2\", \"Player3\"]',7,0,12),(27,'Run way team','[\"Player1\", \"Player12\", \"Player3\"]',7,0,12),(28,'Run way team','[\"Player1\", \"Player12\", \"Player3\"]',7,0,14),(29,'Run way team','[\"Player1\", \"Player12\", \"Player33\"]',7,0,14),(30,'Run way team','[\"Player13\", \"Player12\", \"Player33\"]',7,0,14),(31,'Run way team','[\"Player13\", \"Player232\", \"Player33\"]',7,0,14),(32,'Run way team','[\"Player73\", \"Player232\", \"Player33\"]',7,0,14),(33,'Run way team','[\"Player73\", \"Player252\", \"Player33\"]',7,0,13);
/*!40000 ALTER TABLE `teams` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `transaction_history`
--

DROP TABLE IF EXISTS `transaction_history`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `transaction_history` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `amount` decimal(10,2) NOT NULL,
  `transaction_type` enum('credit','debit') NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  `transaction_date` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `transaction_history_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `transaction_history`
--

LOCK TABLES `transaction_history` WRITE;
/*!40000 ALTER TABLE `transaction_history` DISABLE KEYS */;
INSERT INTO `transaction_history` VALUES (1,4,10.00,'debit','Withdrawal approved by admin','2025-06-25 20:32:47'),(2,7,2500.00,'credit','Prize for rank 1 in contest 11','2025-06-27 13:16:57');
/*!40000 ALTER TABLE `transaction_history` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `transactions`
--

DROP TABLE IF EXISTS `transactions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `transactions` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int DEFAULT NULL,
  `amount` decimal(10,2) DEFAULT NULL,
  `type` enum('credit','debit') NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `transactions_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=19 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `transactions`
--

LOCK TABLES `transactions` WRITE;
/*!40000 ALTER TABLE `transactions` DISABLE KEYS */;
INSERT INTO `transactions` VALUES (1,4,99.99,'debit','Joined contest ID 8','2025-06-24 09:19:24'),(2,4,99.99,'debit','Joined contest ID 8','2025-06-24 09:23:17'),(3,4,99.99,'debit','Joined contest ID 8','2025-06-24 09:23:19'),(4,4,99.99,'debit','Joined contest ID 8','2025-06-24 09:23:19'),(5,4,99.99,'debit','Joined contest ID 8','2025-06-24 09:23:20'),(6,4,200.00,'debit','Withdrawal request Γé╣200','2025-06-24 09:35:00'),(7,4,200.00,'debit','Withdrawal request Γé╣200','2025-06-24 09:41:32'),(8,4,200.00,'debit','Withdrawal request Γé╣200','2025-06-24 09:48:35'),(9,4,200.00,'debit','Withdrawal request Γé╣200','2025-06-24 09:54:06'),(10,4,100.00,'debit','Withdrawal request Γé╣100','2025-06-24 09:58:15'),(11,4,10.00,'debit','Withdrawal request Γé╣10','2025-06-24 10:02:41'),(12,6,50.00,'debit','Joined contest ID 11','2025-06-26 07:44:19'),(13,6,50.00,'debit','Joined contest ID 11','2025-06-26 09:14:01'),(14,6,50.00,'debit','Joined contest ID 11','2025-06-26 09:59:32'),(15,7,50.00,'debit','Joined contest ID 11','2025-06-27 09:21:16'),(16,7,50.00,'debit','Joined contest ID 11','2025-06-27 11:16:25'),(17,7,500.00,'credit','Wallet top-up','2025-06-29 12:50:57'),(18,7,50.00,'debit','Joined contest ID 13','2025-06-30 05:58:22');
/*!40000 ALTER TABLE `transactions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(100) NOT NULL,
  `is_admin` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (1,'sameer','sameer@example.com','123456',0),(2,'YourName','your@email.com','yourpassword',0),(3,'sameer','sameer@email.com','123456',0),(4,'sam','sam@email.com','123456',0),(5,'Admin','admin@example.com','$2b$12$Nhi00ilhvnlU6yLL1y4.t.nP/y3jkdMjg9zmKng.Q5p5/T3GsdBAG',1),(6,'Rob','rob@email.com','$2b$12$2XP2vV6h1GnplHCVigtWFuhZ9cwzcP3rfw100HJLj4XZX1TVm6FAq',0),(7,'Cob','cob@email.com','$2b$12$xaPcSIH5aIROhFKZ9TzFBOhzoWdGl5yi3WYnJ3s89/8/BECGhzdi2',0);
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `wallet_topups`
--

DROP TABLE IF EXISTS `wallet_topups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `wallet_topups` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `amount` decimal(10,2) NOT NULL,
  `status` enum('pending','approved','rejected') DEFAULT 'pending',
  `requested_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `processed_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `wallet_topups_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `wallet_topups`
--

LOCK TABLES `wallet_topups` WRITE;
/*!40000 ALTER TABLE `wallet_topups` DISABLE KEYS */;
/*!40000 ALTER TABLE `wallet_topups` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `wallets`
--

DROP TABLE IF EXISTS `wallets`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `wallets` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int DEFAULT NULL,
  `balance` decimal(10,2) DEFAULT '0.00',
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `wallets_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `wallets`
--

LOCK TABLES `wallets` WRITE;
/*!40000 ALTER TABLE `wallets` DISABLE KEYS */;
INSERT INTO `wallets` VALUES (1,4,580.07,'2025-06-26 07:20:18'),(2,6,50.00,'2025-06-26 09:59:32'),(3,7,3550.00,'2025-06-30 05:58:22');
/*!40000 ALTER TABLE `wallets` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `winners`
--

DROP TABLE IF EXISTS `winners`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `winners` (
  `id` int NOT NULL AUTO_INCREMENT,
  `contest_id` int DEFAULT NULL,
  `team_id` int DEFAULT NULL,
  `total_points` int DEFAULT NULL,
  `rank_position` int DEFAULT NULL,
  `declared_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `contest_id` (`contest_id`),
  KEY `team_id` (`team_id`),
  CONSTRAINT `winners_ibfk_1` FOREIGN KEY (`contest_id`) REFERENCES `contests` (`id`),
  CONSTRAINT `winners_ibfk_2` FOREIGN KEY (`team_id`) REFERENCES `teams` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `winners`
--

LOCK TABLES `winners` WRITE;
/*!40000 ALTER TABLE `winners` DISABLE KEYS */;
INSERT INTO `winners` VALUES (1,8,3,180,1,'2025-06-24 08:15:57'),(2,8,3,180,1,'2025-06-24 08:20:55');
/*!40000 ALTER TABLE `winners` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `withdrawal_requests`
--

DROP TABLE IF EXISTS `withdrawal_requests`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `withdrawal_requests` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `amount` decimal(10,2) NOT NULL,
  `status` enum('pending','approved','rejected') DEFAULT 'pending',
  `requested_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `processed_at` datetime DEFAULT NULL,
  `admin_remark` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `withdrawal_requests_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `withdrawal_requests`
--

LOCK TABLES `withdrawal_requests` WRITE;
/*!40000 ALTER TABLE `withdrawal_requests` DISABLE KEYS */;
INSERT INTO `withdrawal_requests` VALUES (1,4,10.00,'approved','2025-06-24 10:16:31','2025-06-25 20:32:47','Approved successfully'),(2,4,100.00,'rejected','2025-06-25 12:51:50','2025-06-25 20:33:28','Insufficient balance');
/*!40000 ALTER TABLE `withdrawal_requests` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `withdrawals`
--

DROP TABLE IF EXISTS `withdrawals`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `withdrawals` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int DEFAULT NULL,
  `amount` decimal(10,2) DEFAULT NULL,
  `status` varchar(20) DEFAULT 'pending',
  `requested_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `withdrawals_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `withdrawals`
--

LOCK TABLES `withdrawals` WRITE;
/*!40000 ALTER TABLE `withdrawals` DISABLE KEYS */;
INSERT INTO `withdrawals` VALUES (1,4,200.00,'pending','2025-06-24 09:35:00'),(2,4,200.00,'pending','2025-06-24 09:41:32'),(3,4,200.00,'pending','2025-06-24 09:48:35'),(4,4,200.00,'pending','2025-06-24 09:54:06'),(5,4,100.00,'pending','2025-06-24 09:58:15'),(6,4,10.00,'pending','2025-06-24 10:02:41');
/*!40000 ALTER TABLE `withdrawals` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-07-02 11:07:41
