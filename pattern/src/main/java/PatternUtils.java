import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @ClassName: PatternUtils
 * @Description:
 * @Author: Macay
 * @Date: 2021/9/14 11:55 下午
 */
public class PatternUtils {

    // 正则表达式用于匹配${xxx}格式
    private static final Pattern PATTERN = Pattern.compile("(\\$\\{)([\\w\\u4de00-\\u9fa5]+)(\\})");


    /**
     * 将字符串中出现的${xxx}替换为自己想要的数据，使用详见测试类
     * @param context 带${xxx}的字符串
     * @param kvs 要替换的map集合
     * @return
     */
    public static String parse(String context, Map<String, String> kvs) {
        Matcher matcher = PATTERN.matcher(context);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            String group = matcher.group();
            matcher.appendReplacement(sb, kvs.get(group));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }
}
