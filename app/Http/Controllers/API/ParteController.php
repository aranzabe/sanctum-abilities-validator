<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\Parte;
use Illuminate\Http\Request;

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
        $parte = Parte::create($input);
        return response()->json(["success"=>true,"data"=>$parte, "message" => "Created"]);
    }


    public function show($id)
    {
        $parte = Parte::find($id);
        if (is_null($parte)) {
            return response()->json("Parte no encontrado",202);
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

            return response()->json(["success"=>true,"data"=>$parte, "message" => "Updated"]);
        }
    }

    public function destroy($id)
    {
        $parte = Parte::find($id);
        if (is_null($parte)) {
            return response()->json(["success"=>false, "message" => "Not found"]);
        }
        else {
            $parte->delete();
            return response()->json(["success"=>true,"data"=>$parte, "message" => "Deleted"],202);
        }
    }
}
