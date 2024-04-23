package org.ezone.room.repository;

import org.ezone.room.entity.AdminBoard;
import org.ezone.room.repository.search.SearchBoardRepository;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.querydsl.QuerydslPredicateExecutor;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface AdminBoardRepository extends JpaRepository<AdminBoard, Long>, QuerydslPredicateExecutor<AdminBoard>, SearchBoardRepository {

    @Query("select b, w, count(r) from AdminBoard b left join b.member w left outer join AdminReply r on r.adminBoard = b where b.bno = :bno")
    Object getBoardByBno(@Param("bno") Long bno);

}
