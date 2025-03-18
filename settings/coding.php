<?php
	function OnCoding($text)
	{
		return base64_encode($text);      
	}

	function OnEncoding($text)
	{        
		return base64_decode($text);
	}
	
	/* СТАРЫЙ АЛГОРИТМ
	function OnCoding($text)
	{
		$key = "permaviat";
		
		$td = mcrypt_module_open ("tripledes", '', 'cfb', '');
		$iv = mcrypt_create_iv (mcrypt_enc_get_iv_size ($td), MCRYPT_RAND);
		if (mcrypt_generic_init ($td, $key, $iv) != -1) 
			{
			$enc_text=base64_encode(mcrypt_generic ($td,$iv.$text));
			mcrypt_generic_deinit ($td);
			mcrypt_module_close ($td);
			return $enc_text;
			}       
	}

	function strToHex($string)
	{
		$hex='';
		for ($i=0; $i < strlen($string); $i++)
		{
			$hex .= dechex(ord($string[$i]));
		}

		return $hex;
	}

	function OnEncoding($text)
	{        
			$key = "permaviat";
			
			$td = mcrypt_module_open ("tripledes", '', 'cfb', '');
			$iv_size = mcrypt_enc_get_iv_size ($td);
			$iv = mcrypt_create_iv (mcrypt_enc_get_iv_size ($td), MCRYPT_RAND);     
			if (mcrypt_generic_init ($td, $key, $iv) != -1) {
					$decode_text = substr(mdecrypt_generic ($td, base64_decode($text)),$iv_size);
					mcrypt_generic_deinit ($td);
					mcrypt_module_close ($td);
					return $decode_text;
			}
	}

	function hexToStr($hex)
	{
		$string='';
		for ($i=0; $i < strlen($hex)-1; $i+=2)
		{
			$string .= chr(hexdec($hex[$i].$hex[$i+1]));
		}
		return $string;
	}
	*/
?>