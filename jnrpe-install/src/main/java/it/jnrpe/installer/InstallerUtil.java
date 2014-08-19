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
package it.jnrpe.installer;

import java.io.InputStream;
import java.nio.charset.Charset;

public class InstallerUtil {

    public final static boolean ROOT = _init();

    private static boolean _init() {

        try {
            Process p = Runtime.getRuntime().exec("id -u");
            p.waitFor();

            byte[] buff = new byte[50];
            InputStream in = p.getInputStream();

            StringBuilder res = new StringBuilder();
            int iCount;

            while ((iCount = in.read(buff)) > 0) {
                // The default charset must be used...
                res.append(new String(buff, 0, iCount, Charset.defaultCharset()));
            }

            return "0".equals(res.toString().trim());
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }
}
