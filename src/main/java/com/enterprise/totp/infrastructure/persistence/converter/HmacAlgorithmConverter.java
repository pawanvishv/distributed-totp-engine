package com.enterprise.totp.infrastructure.persistence.converter;

import com.enterprise.totp.domain.algorithm.HmacAlgorithm;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;


@Converter(autoApply = true)
public class HmacAlgorithmConverter implements AttributeConverter<HmacAlgorithm, String> {

    @Override
    public String convertToDatabaseColumn(HmacAlgorithm attribute) {
        return attribute == null ? null : attribute.jcaName();
    }

    @Override
    public HmacAlgorithm convertToEntityAttribute(String dbData) {
        return dbData == null ? null : HmacAlgorithm.fromName(dbData);
    }
}

