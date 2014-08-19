package it.jnrpe.utils;

import org.testng.Assert;
import org.testng.annotations.Test;

public class TestElapsed {

    private static class ElapsedTester {
        
        private Elapsed elapsed;
        
        private ElapsedTester() {
            
        }
        
        public static ElapsedTester given(final long qty, TimeUnit unit) {
            ElapsedTester tester = new ElapsedTester();
            tester.elapsed = new Elapsed(qty, unit);
            return tester;
        }
        
        public ElapsedTester expect(TimeUnit unit, long qty) {
            
            switch (unit) {
            case SECOND:
                Assert.assertEquals(elapsed.getSeconds(), qty);
                break;
            case MINUTE:
                Assert.assertEquals(elapsed.getMinutes(), qty);
                break;
            case HOUR:
                Assert.assertEquals(elapsed.getHours(), qty);
                break;
            case DAY:
                Assert.assertEquals(elapsed.getDays(), qty);
                break;
            default:
                Assert.fail(unit + " is not supported");
                break;
            }
            
            return this;
        }
        
        public ElapsedTester expectHours(long hours) {
            Assert.assertEquals(elapsed.getHours(), hours);
            return this;
        }
    }
    
    
    @Test
    public void testParsingMillis() {
        // 5 DAYS + 15 HOURS + 12 MINUTES + 24 SECONDS + 500 MILLIS
        long millis = TimeUnit.DAY.convert(5) + TimeUnit.HOUR.convert(15) + TimeUnit.MINUTE.convert(12) + TimeUnit.SECOND.convert(24)
                + TimeUnit.MILLISECOND.convert(500);

        ElapsedTester.given(millis, TimeUnit.MILLISECOND)
            .expect(TimeUnit.DAY, 5)
            .expect(TimeUnit.HOUR, 15)
            .expect(TimeUnit.MINUTE, 12)
            .expect(TimeUnit.SECOND, 24);
    }
}
