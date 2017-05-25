package com.vitaliy.encryption.rest;


import okhttp3.ResponseBody;
import retrofit2.http.GET;
import rx.Observable;

/**
 * Created by vitaliy on 25.05.17.
 */

public interface GitApi {
    @GET("users/mvvOrigin/repos")
    Observable<ResponseBody> getUserRepositories();
}
