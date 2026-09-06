package com.housedevinci.agentguard.sample;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** An MCP server with one read tool, one write tool that needs a human, a budget of 3 calls. */
@SpringBootApplication
public class SampleApplication {
  public static void main(String[] args) {
    SpringApplication.run(SampleApplication.class, args);
  }
}
