package com.housedevinci.agentguard.architecture;

import static com.tngtech.archunit.base.DescribedPredicate.not;
import static com.tngtech.archunit.core.domain.JavaClass.Predicates.resideInAnyPackage;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

/** The domain boundary: no framework, no JDBC, no Redis client, nothing but the JDK. */
@AnalyzeClasses(
    packages = "com.housedevinci.agentguard",
    importOptions = ImportOption.DoNotIncludeTests.class)
class HexagonalArchitectureTest {

  @ArchTest
  static final ArchRule domain_has_no_framework_imports =
      noClasses()
          .that()
          .resideInAPackage("..domain..")
          .should()
          .dependOnClassesThat(
              // the blanket "javax.." ban is restored (C11); the keyed audit chain's use of
              // javax.crypto.Mac / SecretKeySpec (java.base since JDK 9) is the only carve-out —
              // javax.naming, javax.management, javax.net and javax.xml (XXE) stay forbidden
              resideInAnyPackage("javax..")
                  .and(not(resideInAnyPackage("javax.crypto..")))
                  .or(
                      resideInAnyPackage(
                          "org.springframework..",
                          "jakarta..",
                          "java.sql..",
                          "redis.clients..",
                          "org.slf4j..",
                          "com.fasterxml..",
                          "tools.jackson..",
                          "io.modelcontextprotocol..",
                          "..application..",
                          "..adapter..")));

  @ArchTest
  static final ArchRule application_depends_only_on_domain_and_jdk =
      noClasses()
          .that()
          .resideInAPackage("..application..")
          .should()
          .dependOnClassesThat()
          .resideInAnyPackage(
              "org.springframework..",
              "jakarta..",
              "javax..",
              "java.sql..",
              "redis.clients..",
              "io.modelcontextprotocol..",
              "..adapter..");

  @ArchTest
  static final ArchRule adapters_never_reach_into_each_other =
      noClasses()
          .that()
          .resideInAPackage("..adapter.jdbc..")
          .should()
          .dependOnClassesThat()
          .resideInAnyPackage("..adapter.redis..", "..adapter.notify..", "..adapter.memory..");
}
