<?php

namespace App\Http\Controllers;
/**
 * Dev Ruben Consuegra - Good Vibres
 */
use Illuminate\Http\Request;
use App\Models\User;
use App\Models\Token;
use Illuminate\Support\Str;

class LoginController extends Controller
{
    private $email_admin = 'admin@admin.com';
    private $password_admin = 'admin';
    private $default_jump_ascii = 5;
    private $defaul_iv = '1234567891234567';
    /**
     * Consulta los usuarios
     */
    public function queryAllUsers(Request $request)
    {
        $response = "";
        $token = $request->get('token');
        if ($token)
        {
            $token_table = Token::find(1);
            if ($token_table)
            {
                $token_public = $token_table->token_access;
                if ($token_public === $token)
                {
                    $information_decryp = $this->decrypInfoWithTokensAndAutenticate(null, null);
                    $response = response($information_decryp, 200);
                }
                else
                {
                    $response = response('Token de autorización incorrecto', 400);
                }
            }
            else
            {
                $response = response('Tokens no parametrizados', 500);
            }
        }
        else
        {
            $response = response('No hay token de autorización', 404);
        }
        return $response;
    }

    /**
     * Retorna la consulta de usuarios
     */
    public function createUser(Request $request)
    {
        $response = "";
        try
        {
            $email = $request->get('email');
            $user_registred = User::where('email', $email)->first();
            if (!$user_registred)
            {
                $user_save = new User();
                $user_save->name = $request->get('name');
                $user_save->email = $request->get('email');
                $user_save->document = $request->get('document');
                $user_save->phone = $request->get('phone');
                $user_save->password = $request->get('password');
                $token_table = Token::find(1);
                $token_master = $token_table->token_master_admin;
                $token_info =  $token_table->token_decryp_information;
                $token_master_decrypt = $this->decryptTokenMaster($token_master);
                $token_info_decrypt = $this->decryptTokenInfo($token_info,$token_master_decrypt);
                $user = $this->encryptInfo($user_save,$token_info_decrypt,false);
                $response = response(array('respuesta'=>'Usuario creado correctamente'), 200);
            }else
            {
                $response = response(array('respuesta'=>'Email ya existe') , 400);
            }
        }catch (\Exception $e)
        {
            $response = response('Error interno del servidor' . $e, 500);
        }
        return $response;
    }

    /**
     * Retorna el login del aplicativo
     */
    public function login(Request $request)
    {
        $response = '';
        $email = $request->get('email');
        $password = $request->get('password');
        if ($email === $this->email_admin && $password === $this->password_admin)
        {
            $user = (['name' => 'admin','email' => $this->email_admin,'phone' => '123456789','document' => '789456123']);
            $response = response($user,200);
        }else
        {
            $information_decrypt = $this->decrypInfoWithTokensAndAutenticate($email,$password);
            $response = response($information_decrypt != null ? $information_decrypt : 'Email y contraseña erroneas', $information_decrypt != null ? 200 : 404);
        }
        return $response;
    }

    /**
     *Muestra los tokens registrados
     */
    public function showTokens(Request $request)
    {
        $response = '';
        $user = $request->get('user_special');
        if ($user === 'admin')
        {
            $response = response(Token::all(), 200);
        }
        else
        {
            $response = response('Acceso prohibido',403);
        }
        return $response;
    }

    /**
     * Edita los tokens maestros
     */
    public function editTokensMaster(Request $request)
    {
        $newMagicWorldAdmin = $request->get('admin_word_token');
        $newMagicWorldInfo = $request->get('admin_word_info');
        $response = '';
        if (trim($newMagicWorldAdmin) != "" && trim($newMagicWorldInfo) != "")
        {
            try
            {
                /**
                 * Descifrado para colocar nuevos tokens
                 */
                $token_table = Token::find(1);
                $token_master = $token_table->token_master_admin;
                $token_info =  $token_table->token_decryp_information;
                if ($token_master === 'DEFAULT' && $token_info === 'DEFAULT')
                {
                    $token_table->token_master_admin = $this->encryptTokenMaster($newMagicWorldAdmin);
                    $token_table->token_decryp_information = $this->encryptTokenInfo($newMagicWorldInfo,$newMagicWorldAdmin);
                    $token_table->save();
                    $response = response($token_table, 200);
                }
                else
                {
                    $token_master_decrypt = $this->decryptTokenMaster($token_master);
                    $token_info_decrypt = $this->decryptTokenInfo($token_info,$token_master_decrypt);
                    $information_decrypt = $this->decryptInfo(User::all(),$token_info_decrypt,true);
                    /**
                     * Cifrado para volver a cifrar y colocar nuevos tokens
                     */
                    $token_table->token_master_admin = $this->encryptTokenMaster($newMagicWorldAdmin);
                    $token_table->token_decryp_information = $this->encryptTokenInfo($newMagicWorldInfo,$newMagicWorldAdmin);
                    $token_table->save();
                    $information_encrypt = $this->encryptInfo($information_decrypt, $newMagicWorldInfo,true);
                    $response = response(array('respuesta'=>'Tokens cambiados e información cifrada'), 200);
                }
            }
            catch (\Exception $e)
            {
                $response = response('Ocurrio un error en el servidor \n' . $e, 500);
            }
        }else
        {
            $response = response('Las dos palabras secretas son obligatorias', 400);
        }
        return $response;
    }

    /**
     * Edita el token publico
     */
    public function editTokenPublic(Request $request)
    {
        $publicToken = $request->get('token_public');
        $response = '';
        try
        {
            $tokens = Token::find(1);
            if ($publicToken === $tokens->token_access)
            {
                $tokens->token_access = uniqid(base64_encode(Str::random(40)));
                $tokens->save();
                $response = response($tokens, 200);
            }
            else{
                $response = response('El token publico no corresponde al que se tiene guardado', 404);
            }
        }
        catch (\Exception $e)
        {
            $response = response('Ocurrio un error inesperado' . $e, 500);
        }
        return $response;
    }


    /**
     * Metodos utilitarios que realizan funciones de consulta, cifrado y decifrado de info
     */

    /**
     *Descripta información consultando las tablas correspondientes
     */
    public function decrypInfoWithTokensAndAutenticate($email, $password)
    {
        $token_table = Token::find(1);
        $token_master = $token_table->token_master_admin;
        $token_info =  $token_table->token_decryp_information;
        $token_master_decrypt = $this->decryptTokenMaster($token_master);
        $token_info_decrypt = $this->decryptTokenInfo($token_info,$token_master_decrypt);
        $information_decryp = null;
        if ($email && $password)
        {
            $user = User::where('email', $email)->first();
            if ($user)
            {
                $information_decryp = $this->decryptInfo($user,$token_info_decrypt,false);
                $password_user_decryp = $information_decryp->password;
                if(!$password === $password_user_decryp)
                {
                    $information_decryp = null;
                }
            }
        }
        else
        {
            $information_decryp = $this->decryptInfo(User::all(),$token_info_decrypt, true);
        }
        return $information_decryp;
    }



    /**
     * Encripta la información del usuario
     */
    public function encryptInfo($users,$password,$massiveEncrypt)
    {
        if ($massiveEncrypt)
        {
            foreach ($users as $user)
            {
               $this->encryptInfoProcess($user,$password);
            }
        }else{
                $this->encryptInfoProcess($users,$password);
        }
        return $users;
    }

    /** Proceso para cifrar la información
     * @param $user
     * @param $password
     * @return mixed
     */
    public function encryptInfoProcess($user, $password)
    {
        $user->name = openssl_encrypt($user->name,"AES-256-CBC", $password,0,$this->defaul_iv);
        $user->document = openssl_encrypt($user->document,"AES-256-CBC", $password,0,$this->defaul_iv);
        $user->phone = openssl_encrypt($user->phone,"AES-256-CBC", $password,0,$this->defaul_iv);
        $user->password = openssl_encrypt($user->password,"AES-256-CBC", $password,0,$this->defaul_iv);
        $user->save();
        return $user;
    }


    /**
     * Descifra la información cifrada en base de datos
     */
    public function decryptInfo($users,$password,$massiveDecryp)
    {
        if ($massiveDecryp)
        {
            foreach ($users as $user)
            {
                $this->decryptInfoProcess($user,$password);
            }
        }
        else
        {

            $this->decryptInfoProcess($users,$password);
        }
        return $users;
    }

    /**Metodo que hace el proceso de decifrado de la información
     * @param $user
     * @param $password
     * @return mixed
     */

    public function decryptInfoProcess($user, $password)
    {
        $user->name = openssl_decrypt($user->name,"AES-256-CBC", $password,0,$this->defaul_iv);
        $user->document = openssl_decrypt($user->document,"AES-256-CBC", $password,0,$this->defaul_iv);
        $user->phone = openssl_decrypt($user->phone,"AES-256-CBC", $password,0,$this->defaul_iv);
        $user->password = openssl_decrypt($user->password,"AES-256-CBC", $password,0,$this->defaul_iv);

        return $user;
    }


    /**
     * Cifra el token de información
     */
    public function encryptTokenInfo($tokenInfo, $password)
    {
        return openssl_encrypt($tokenInfo, "AES-256-CBC", $password, 0,$this->defaul_iv);
    }


    /**
     * Descifra el token de cifrado de información
     */
    public function decryptTokenInfo($tokenInfo, $password)
    {
        return openssl_decrypt($tokenInfo, "AES-256-CBC", $password, 0,$this->defaul_iv);
    }


    /**
     * Cifra el token maestro
     */
    public function encryptTokenMaster($tokenMaster)
    {
        $token_array_char_decrypt = str_split($tokenMaster,1);
        $token_array_char_encrypt = [];
        foreach ($token_array_char_decrypt as $item) {

            $number_ascii_decrypt = ord($item) + $this->default_jump_ascii;
            $char = chr($number_ascii_decrypt);
            array_push($token_array_char_encrypt, $char);
        }
        return implode($token_array_char_encrypt);
    }


    /**
     * Descifra el token maestro para decifrar el token de información
     */
    public function decryptTokenMaster($tokenMaster)
    {
        $token_array_char_encrypt = str_split($tokenMaster,1);
        $token_array_char_decrypt = [];
        foreach ($token_array_char_encrypt as $item) {

            $number_ascii_encrypt = ord($item) - $this->default_jump_ascii;
            $char = chr($number_ascii_encrypt);
            array_push($token_array_char_decrypt,$char);
        }
        return implode($token_array_char_decrypt);
    }

}
