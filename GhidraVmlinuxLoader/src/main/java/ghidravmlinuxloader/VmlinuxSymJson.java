package ghidravmlinuxloader;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;

import com.google.gson.Gson;

public class VmlinuxSymJson {
	public int arch;
	public BigInteger _start;
	public int numsyms;
	public BigInteger[] address;
	public String[] type;
	public String[] name;
	public BigInteger address_table;
	public BigInteger name_table;
	public BigInteger type_table;
	public BigInteger table_index_table;
	public String linux_banner;
	
	public static VmlinuxSymJson loadSymJson(Path symFilePath) throws IOException
	{
		byte[] jsonStrBytes = Files.readAllBytes(symFilePath);
		String jsonStr = new String(jsonStrBytes, Charset.forName("UTF-8"));
		
		Gson gson = new Gson();
		VmlinuxSymJson symJson = gson.fromJson(jsonStr, VmlinuxSymJson.class);
		return symJson;
	}
}
