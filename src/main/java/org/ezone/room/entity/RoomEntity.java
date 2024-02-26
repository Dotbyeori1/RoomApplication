package org.ezone.room.entity;

import jakarta.persistence.*;
import lombok.*;
import org.ezone.room.constant.Tag;

import java.util.ArrayList;
import java.util.List;

//방 엔티티
@Entity
@Table(name = "room")
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Data
public class RoomEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long rno;  //방번호

    @Column(length = 30,nullable = false)
    private String room_name; //방 이름
    @Column(nullable = false)
    private int price; //방 갸격

    @Column(name ="operating")
    private boolean operating;

    private String content;

    private int tag; // 태그

    @OneToMany(mappedBy = "room_id", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ReservationEntity> reservations = new ArrayList<>();

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ano",nullable = false)
    private AccommodationEntity accommodationEntity; //어디 소속 숙소의 방인지 알아야되니까 중계어플에서는 필수.

    public void addTag(Tag newTag) {
        this.tag |= newTag.getValue();  // this.tag = this.tag | new.getValue();
    }
    public void removeTag(Tag targetTag) {
        this.tag &= ~targetTag.getValue(); // this.tag = this.tag & targetTag.getValue();
    }
    public boolean hasTag(Tag checkTag) {
        return (this.tag & checkTag.getValue()) == checkTag.getValue();
        //(비트연산) == 체크
    }
}
