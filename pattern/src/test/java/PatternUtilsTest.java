import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PatternUtilsTest {

    @Test
    void parse() {
        String context = "${姓名}您好，您的登录密码未${password}";

        Map<String, String> machter = new HashMap<>();
        machter.put("${姓名}", "lisi");
        machter.put("${password}", "Aa@111111");

        String parse = PatternUtils.parse(context, machter);
        System.out.println(parse); //lisi您好，您的登录密码未Aa@111111

    }
}
