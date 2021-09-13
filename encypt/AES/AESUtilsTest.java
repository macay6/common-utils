import org.junit.Test;

class AESUtilsTest {
    @Test
    public void encrypt() {
        String encrypt = AESUtils.encrypt("123456");
        System.out.println(encrypt);

    }

}
