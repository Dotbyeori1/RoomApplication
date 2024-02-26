package org.ezone.room.repository;

import org.ezone.room.entity.ReviewBoard;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ReviewBoardRepository extends JpaRepository<ReviewBoard, Long> {

    Page<ReviewBoard> findByAccommodation_Ano(Long ano, Pageable pageable);

    @Query("SELECT r FROM ReviewBoard r join Accomodation a on r.accommodation.ano = a.ano " +
            "join Member m on a.member.id = m.id where m.id =:id")
    Page<ReviewBoard> findAccommodationByMemberId(@Param("id") String id, Pageable pageable);

    List<ReviewBoard> findByRoom_Rno(Long rno);

    @Query("SELECT COUNT(rb) > 0 FROM ReviewBoard rb WHERE rb.reservation.rvno = :rvno")
    boolean existsByReviewBoard(@Param("rvno") Long rvno);

    void deleteByRoom_Rno(Long rno);
}
