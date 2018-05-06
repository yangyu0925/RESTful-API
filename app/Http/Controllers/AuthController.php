<?php

namespace App\Http\Controllers;

use App\User;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        $this->validate($request, [
            'name' => 'required',
            'email' => 'required|email',
            'password' => 'required|min:6'
        ]);

        $name = $request->input('name');
        $email = $request->input('email');
        $password = $request->input('password');

        $user = new User([
            'name' => $name,
            'email' => $email,
            'password' => bcrypt($password)
        ]);

        $credentials = [
            'email' => $email,
            'password' => $password
        ];

        if ($user->save()) {
            $token = null;
            try {
                if (!$token = JWTAuth::attempt($credentials)) {
                    return response()->json([
                        'message' => 'Email or Password are incorrect',
                    ], 404);
                }
            } catch (JWTAuthException $e) {
                return response()->json([
                    'message' => 'failed_to_create_token',
                ],404);
            }

            $user->sigin= [
                'href' => '/api/v1/user/sigin',
                'method' => 'POST',
                'params' => 'email, password'
            ];
            $response = [
                'msg' => 'User created',
                'user' => $user,
                'token' => $token
            ];
            return response()->json($response, 201);
        }

        $response = [
            'msg' => 'An error occurred'
        ];

        return response()->json($response, 404);
    }

    public function signin(Request $request)
    {
        $this->validate($request, [
            'email' => 'required|email',
            'password' => 'required|min:5'
        ]);
        $email = $request->input('email');
        $password = $request->input('password');

        if ($user = User::where('email', $email)->first()){
            $credentials = [
                'email' => $email,
                'password' => $password
            ];
            $token = null;
            try {
                if (!$token = JWTAuth::attempt($credentials)) {
                    return response()->json([
                        'message' => 'Email or Password are incorrect',
                    ], 404);
                }
            } catch (JWTAuthException $e) {
                return response()->json([
                    'message' => 'failed_to_create_token',
                ],404);
            }
            $response = [
                'message' => 'User signin',
                'user' => $user,
                'token' => $token
            ];
            return response()->json($response, 201);
        }
        $response = [
            'message' => 'An error occurred'
        ];
        return response()->json($response, 404);
    }
}
