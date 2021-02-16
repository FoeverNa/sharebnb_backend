package com.mip.sharebnb.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Email;
import javax.validation.constraints.Past;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.time.LocalDate;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GoogleMemberDto {

    @Email(message = "이메일 형식이 아닙니다")
    private String email;

    @Size(min = 2, max = 50, message = "이름은 2자 이상 50자 이하여야 합니다.")
    @Pattern(regexp="^[가-힣]*$" , message = "이름은 한글로만 입력해주세요")
    private String name;

    @Size(min = 11, max = 11, message = "연락처는 11자리로 입력해주세요")
    @Pattern(regexp="^[0-9]*$" , message = "연락처는 숫자로만 입력해주세요")
    private String contact;

    @Past
    private LocalDate birthDate;

    private String socialId;

}
