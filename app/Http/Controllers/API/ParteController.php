<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\Parte;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class ParteController extends Controller
{
    public function index()
    {
        $partes = Parte::all();
        return response()->json($partes,200);
    }


    public function store(Request $request)
    {
        $input = $request->all();
        $rules = [
            'nombre' => 'required|string|max:255',
            'causa' => 'required|in:Nada,Todo,"Me tiene mania"',
            'gravedad' => 'required|in:Leve,Destierro,"Pasar por la quilla"',
            // 'observaciones' => 'required|string|max:255'
        ];
        $messages = [
            'required' => 'El campo :attribute es obligatorio.',
            'in' => 'El campo :attribute debe ser uno de los siguientes valores: :values.'
        ];

        $validator = Validator::make($input, $rules, $messages);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $parte = Parte::create($input);
        return response()->json(["success"=>true,"data"=>$parte, "message" => "Created"],201);
    }


    public function show($id)
    {
        $parte = Parte::find($id);
        if (is_null($parte)) {
            return response()->json("Parte no encontrado",404);
        }
        return response()->json(["success"=>true,"data"=>$parte, "message" => "Retrieved"]);
    }


    public function update($id, Request $request)
    {
        $input = $request->all();


        $parte = Parte::find($id);
        if (is_null($parte)) {
            return response()->json(["success"=>false, "message" => "Not found"]);
        }
        else {
            $parte->nombre = $input['nombre'];
            $parte->causa = $input['causa'];
            $parte->save();

            return response()->json(["success"=>true,"data"=>$parte, "message" => "Updated"], 200);
        }
    }

    public function destroy($id)
    {
        $parte = Parte::find($id);
        if (is_null($parte)) {
            return response()->json(["success"=>false, "message" => "Not found"],404);
        }
        else {
            $parte->delete();
            return response()->json(["success"=>true,"data"=>$parte, "message" => "Deleted"], 200);
        }
    }
}
