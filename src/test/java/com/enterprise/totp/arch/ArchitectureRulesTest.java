package com.enterprise.totp.arch;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;

class ArchitectureRulesTest {

    private static JavaClasses importedClasses;

    @BeforeAll
    static void importClasses() {
        importedClasses = new ClassFileImporter()
                .importPackages("com.enterprise.totp");
    }

    @Test
    void domainLayerMustNotImportSpring() {
        ArchRule rule = noClasses()
                .that().resideInAPackage("..domain..")
                .should().dependOnClassesThat()
                .resideInAPackage("org.springframework..");

        rule.check(importedClasses);
    }

    @Test
    void domainLayerMustNotImportJakartaPersistence() {
        ArchRule rule = noClasses()
                .that().resideInAPackage("..domain..")
                .should().dependOnClassesThat()
                .resideInAPackage("jakarta.persistence..");

        rule.check(importedClasses);
    }

    @Test
    void apiDtosMustNotReferenceInfrastructureEntities() {
        ArchRule rule = noClasses()
                .that().resideInAPackage("..api.dto..")
                .should().dependOnClassesThat()
                .resideInAPackage("..infrastructure.persistence.entity..");

        rule.check(importedClasses);
    }

    @Test
    void applicationLayerMustNotImportControllers() {
        ArchRule rule = noClasses()
                .that().resideInAPackage("..application..")
                .should().dependOnClassesThat()
                .resideInAPackage("..api.controller..");

        rule.check(importedClasses);
    }

    @Test
    void auditingDecoratorMustBePrimary() {
        ArchRule rule = classes()
                .that().haveSimpleName("AuditingMfaVerificationDecorator")
                .should().beAnnotatedWith(org.springframework.context.annotation.Primary.class);

        rule.check(importedClasses);
    }
}

