package org.ezone.room.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.ezone.room.dto.*;
import org.ezone.room.entity.Member;
import org.ezone.room.repository.MemberRepository;
import org.ezone.room.security.CustomUserDetails;
import org.ezone.room.security.TokenProvider;
import org.ezone.room.service.AccommodationService;
import org.ezone.room.service.TourBoardService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import java.time.LocalDate;
import java.util.Objects;

@Controller
@Log4j2
@RequiredArgsConstructor
public class MainController {

    @Value("${jwt.secret-key}")
    private String secretKey;


    private final TokenProvider tokenProvider;
    private final TourBoardService tourBoardService;
    private final AccommodationService accommodationService;
    private final MemberRepository memberRepository;

    @GetMapping("")
    public String intro(Model model){

        return "intro";
    }

    @PostMapping("oauth")
    public ResponseEntity<?> oauthSuccess (@RequestParam(value = "oauth", required = false) String oauth){
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        MemberFormDto memberFormDto = new MemberFormDto();
        if (principal instanceof CustomUserDetails && Objects.equals(oauth, "true")) {
            Member member = ((CustomUserDetails) principal).getMember();
            String token = tokenProvider.create((CustomUserDetails) principal, secretKey);
            memberFormDto.setRole(member.getRole());
            memberFormDto.setToken(token);
            String refreshToken = tokenProvider.createRefreshToken((CustomUserDetails) principal, secretKey);
            member.setRefreshToken(refreshToken);
            memberRepository.save(member);
        }
        return ResponseEntity.ok(memberFormDto);
    }

    @PostMapping(value = "auth")
    private ResponseEntity<?> auth(MemberFormDto memberFormDto, Authentication authentication,
                                   HttpServletRequest request, HttpServletResponse response) {

        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Member member = null;
        if (principal instanceof CustomUserDetails) {
            member = ((CustomUserDetails) principal).getMember();

            if (tokenProvider.isTokenExpired(member.getRefreshToken(), secretKey)) {
                ResponseDTO responseDTO = new ResponseDTO();
                responseDTO.setError("재로그인이 필요합니다.");
                SecurityContextLogoutHandler securityContextLogoutHandler = new SecurityContextLogoutHandler();
                securityContextLogoutHandler.setInvalidateHttpSession(true); // 세션 무효화 처리
                securityContextLogoutHandler.logout(request, response, authentication); // 로그아웃 처리
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseDTO);
            }

            String token = tokenProvider.create((CustomUserDetails) principal, secretKey);
            memberFormDto.setToken(token);
        } else {
            ResponseDTO responseDTO = new ResponseDTO();
            responseDTO.setError("인증되지 않은 사용자 또는 세션이 만료되었습니다.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseDTO);
        }
        return ResponseEntity.ok(memberFormDto);
    }

    @GetMapping(value = "main")
    public String main(Model model) {
        int page = 1;
        int pageSize = 10;
        PageRequestDTO pageRequestDTO = new PageRequestDTO(page, pageSize);
        PageResultDTO<TourBoardDTO, Object[]> tourBoard = tourBoardService.getList(pageRequestDTO,
                pageRequestDTO.getType(), pageRequestDTO.getKeyword(), pageRequestDTO.getCategory(), pageRequestDTO.getRegion());

        model.addAttribute("tourBoard", tourBoard);

        return "main";
    }

    @GetMapping(value = "search")
    public String search(@RequestParam("keyword") String keyword,
                         @RequestParam(value = "page", required = false, defaultValue = "1") int page, Model model) {

        int pageSize = 10;
        PageRequestDTO pageRequestDTO = new PageRequestDTO(page, pageSize);
        LocalDate startDate = LocalDate.now();
        LocalDate endDate = LocalDate.now().plusDays(1);

        Integer min = null, max = null;
        Integer tag = null;

        PageResultDTO<TourBoardDTO, Object[]> tourBoard = tourBoardService.getList(pageRequestDTO,
                pageRequestDTO.getType(), keyword, pageRequestDTO.getCategory(), pageRequestDTO.getRegion());
        PageResultDTO<AccommodationDTO, Object[]> accommodation = accommodationService.searchAccommodationList(pageRequestDTO,
                keyword, pageRequestDTO.getCategory(), pageRequestDTO.getRegion(), startDate, endDate, min, max, tag);

        model.addAttribute("tourBoard", tourBoard);
        model.addAttribute("accommodation", accommodation);

        return "search";
    }
}
