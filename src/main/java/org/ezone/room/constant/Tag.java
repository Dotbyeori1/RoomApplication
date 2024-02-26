package org.ezone.room.constant;

public enum Tag {
    FREE_WIFI(1), // 무료와이파이
    POOL(2), // 수영장
    BREAKFAST(4), // 아침
    PARKING(8), // 주차장
    GYM(16), // 체육관
    SEAVIEW(32), // 바다뷰
    LAKEVIEW(64), // 호수뷰
    NOSMOKING(128); //금연

    private final int value;

    Tag(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
