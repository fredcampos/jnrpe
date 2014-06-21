/*******************************************************************************
 * Copyright (c) 2007, 2014 Massimiliano Ziccardi
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package it.jnrpe.utils;

import java.math.BigDecimal;

import org.testng.Assert;
import org.testng.annotations.Test;

@SuppressWarnings("deprecation")
public class ThresholdUtilTest {

    @Test
    public void testSimpleThreshold() throws BadThresholdException {
        Assert.assertTrue(ThresholdUtil.isValueInRange("10", 5));
        Assert.assertTrue(ThresholdUtil.isValueInRange("10", 0));
        Assert.assertTrue(ThresholdUtil.isValueInRange("10", 10));
        Assert.assertFalse(ThresholdUtil.isValueInRange("10", -1));
        Assert.assertFalse(ThresholdUtil.isValueInRange("10", 11));

    }

    @Test
    public void testToInfinity() throws BadThresholdException {
        Assert.assertTrue(ThresholdUtil.isValueInRange("10:", 10));
        Assert.assertTrue(ThresholdUtil.isValueInRange("10:", 100));
        Assert.assertTrue(ThresholdUtil.isValueInRange("10:", 1000));
        Assert.assertFalse(ThresholdUtil.isValueInRange("10:", 9));
        Assert.assertFalse(ThresholdUtil.isValueInRange("10:", -11));
    }

    @Test
    public void testToInfinityExplicit() throws BadThresholdException {
        Assert.assertTrue(ThresholdUtil.isValueInRange("10:~", 10));
        Assert.assertTrue(ThresholdUtil.isValueInRange("10:~", 100));
        Assert.assertTrue(ThresholdUtil.isValueInRange("10:~", 1000));
        Assert.assertFalse(ThresholdUtil.isValueInRange("10:~", 9));
        Assert.assertFalse(ThresholdUtil.isValueInRange("10:~", -11));
    }

    @Test
    public void testNegativeInfinity() throws BadThresholdException {
        Assert.assertTrue(ThresholdUtil.isValueInRange("~:10", 10));
        Assert.assertTrue(ThresholdUtil.isValueInRange("~:10", -10));
        Assert.assertTrue(ThresholdUtil.isValueInRange("~:10", -100));
        Assert.assertTrue(ThresholdUtil.isValueInRange("~:10", -1000));
        Assert.assertFalse(ThresholdUtil.isValueInRange("~:10", 11));
        Assert.assertFalse(ThresholdUtil.isValueInRange("~:10", 100));
        Assert.assertFalse(ThresholdUtil.isValueInRange("~:10", 1000));
    }

    @Test
    public void testBounded() throws BadThresholdException {
        Assert.assertTrue(ThresholdUtil.isValueInRange("10:20", 10));
        Assert.assertTrue(ThresholdUtil.isValueInRange("10:20", 15));
        Assert.assertTrue(ThresholdUtil.isValueInRange("10:20", 20));
        Assert.assertFalse(ThresholdUtil.isValueInRange("10:20", 9));
        Assert.assertFalse(ThresholdUtil.isValueInRange("10:20", 21));
        Assert.assertFalse(ThresholdUtil.isValueInRange("10:20", -10));
    }

    @Test
    public void testNegatedBounded() throws BadThresholdException {
        Assert.assertFalse(ThresholdUtil.isValueInRange("@10:20", 10));
        Assert.assertFalse(ThresholdUtil.isValueInRange("@10:20", 15));
        Assert.assertFalse(ThresholdUtil.isValueInRange("@10:20", 20));
        Assert.assertTrue(ThresholdUtil.isValueInRange("@10:20", 9));
        Assert.assertTrue(ThresholdUtil.isValueInRange("@10:20", 21));
        Assert.assertTrue(ThresholdUtil.isValueInRange("@10:20", -10));
    }

    @Test(expectedExceptions = BadThresholdException.class)
    public void testMalformedNegation() throws BadThresholdException {
        ThresholdUtil.isValueInRange("10:@20", 10);
    }

    @Test(expectedExceptions = BadThresholdException.class)
    public void testBadSeparator() throws BadThresholdException {
        ThresholdUtil.isValueInRange("10:20:", 10);
    }

    @Test(expectedExceptions = BadThresholdException.class)
    public void testEmptyNumbers() throws BadThresholdException {
        ThresholdUtil.isValueInRange(":", 10);
    }

    @Test(expectedExceptions = BadThresholdException.class)
    public void testEmptyNumbersJustSign() throws BadThresholdException {
        ThresholdUtil.isValueInRange("+:", 10);
    }

    @Test
    public void testMissingLeft() throws BadThresholdException {
        Assert.assertTrue(ThresholdUtil.isValueInRange(":20", 10));
        Assert.assertTrue(ThresholdUtil.isValueInRange(":20", 20));
        Assert.assertFalse(ThresholdUtil.isValueInRange(":20", 21));
        Assert.assertFalse(ThresholdUtil.isValueInRange(":20", -5000));
    }

    @Test
    public void testMissingRight() throws BadThresholdException {
        Assert.assertFalse(ThresholdUtil.isValueInRange("20:", 10));
        Assert.assertTrue(ThresholdUtil.isValueInRange("20:", 20));
        Assert.assertTrue(ThresholdUtil.isValueInRange("20:", 21));
        Assert.assertFalse(ThresholdUtil.isValueInRange("20:", -5000));
    }

    @Test
    public void testMissingRightLong() throws BadThresholdException {
        Assert.assertFalse(ThresholdUtil.isValueInRange("20:", 10L));
        Assert.assertTrue(ThresholdUtil.isValueInRange("20:", 20L));
        Assert.assertTrue(ThresholdUtil.isValueInRange("20:", 21L));
        Assert.assertFalse(ThresholdUtil.isValueInRange("20:", -5000L));
    }

    @Test
    public void testMissingRightBigDecimal() throws BadThresholdException {
        Assert.assertFalse(ThresholdUtil.isValueInRange("20:", new BigDecimal(10)));
        Assert.assertTrue(ThresholdUtil.isValueInRange("20:", new BigDecimal(20)));
        Assert.assertTrue(ThresholdUtil.isValueInRange("20:", new BigDecimal(21)));
        Assert.assertFalse(ThresholdUtil.isValueInRange("20:", new BigDecimal(-5000)));
    }

}
