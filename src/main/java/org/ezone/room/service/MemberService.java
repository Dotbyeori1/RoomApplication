package org.ezone.room.service;

import org.springframework.stereotype.Service;
import lombok.extern.log4j.Log4j2;
import org.ezone.room.dto.MemberFormDto;
import org.ezone.room.entity.Member;
import org.ezone.room.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;

import jakarta.transaction.Transactional;

@Service
@Log4j2
@Transactional
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;

//    @Autowired
//    private JavaMailSender emailSender; //이메일 전송해주는 기능을 DI받음

    @Autowired
    PasswordEncoder passwordEncoder;

    // 비밀번호 암호화
    @Autowired
    public MemberService(MemberRepository memberRepository, PasswordEncoder passwordEncoder) {
        this.memberRepository = memberRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // 회원가입
    public Member saveMember(Member member) {
        vaildateDuplicateMember(member);
        return  memberRepository.save(member);
    }
    // 중복 회원 가입 막기
    private void vaildateDuplicateMember(Member member){
        Member findMember = memberRepository.findByEmail(member.getEmail());
        if(findMember != null){
            throw new IllegalStateException("이미 가입된 회원입니다.");
        }
    }

    public Member editMember(MemberFormDto memberFormDto){
        Member member = memberRepository.findByEmail(memberFormDto.getEmail());
        member.setTel(memberFormDto.getTel());
        member.setName(memberFormDto.getName());
        member.setNickName(memberFormDto.getNickName());
        memberRepository.save(member);
        return member;
    }

    public Member changePassword(MemberFormDto memberFormDto){
        Member member = memberRepository.findByEmail(memberFormDto.getEmail());
        System.out.println(memberFormDto.getPassword());
        member.setPassword(passwordEncoder.encode(memberFormDto.getPassword()));
        memberRepository.save(member);

        return member;
    }

    public Member changeSeller(MemberFormDto memberFormDto){
        Member member = memberRepository.findByEmail(memberFormDto.getEmail());
        member.setRole(memberFormDto.getRole());
        member.setName(memberFormDto.getName());
        member.setTel(memberFormDto.getTel());
        memberRepository.save(member);
        return member;
    }

//    // 비밀번호 찾기 메일
//    public void sendEmail(String to, String subject, String text){
//        SimpleMailMessage message = new SimpleMailMessage(); //메일 객체 생성
//        message.setTo(to);
//        message.setSubject(subject);
//        message.setText(text);
//        emailSender.send(message); //이메일 전송 기능을 통해서 위에서 생성한 메일 객체를 전송
//    }

} //class
