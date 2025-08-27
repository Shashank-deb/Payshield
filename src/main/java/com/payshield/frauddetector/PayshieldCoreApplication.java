package com.payshield.frauddetector;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication(scanBasePackages = "com.payshield.frauddetector")
@EnableJpaRepositories(basePackages = "com.payshield.frauddetector.infrastructure.jpa")
@EntityScan(basePackages = "com.payshield.frauddetector.infrastructure.jpa")
public class PayshieldCoreApplication {
	public static void main(String[] args) {
		SpringApplication.run(PayshieldCoreApplication.class, args);
	}
}
