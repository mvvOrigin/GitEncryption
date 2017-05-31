package com.vitaliy.encryption.ui;

import android.databinding.DataBindingUtil;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;

import com.vitaliy.data.TouchData;
import com.vitaliy.encryption.R;
import com.vitaliy.encryption.databinding.ActivityMainBinding;

/**
 * Created by vitaliy on 25.05.17.
 */

public class RepositoryActivity extends AppCompatActivity implements RepositoryContract.View, View.OnClickListener {
    private ActivityMainBinding binding;
    private RepositoryContract.TouchPresenter presenter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = DataBindingUtil.setContentView(this, R.layout.activity_main);
        presenter = new TouchDataPresenter(this);
        setProgressVisible(false);
        binding.btnLoadRepos.setOnClickListener(this);
    }

    @Override
    public void showMessage(String string) {
        binding.tvMessage.setText(string);
    }

    @Override
    public void setProgressVisible(boolean visible) {
        binding.prLoading.setVisibility(visible ? View.VISIBLE : View.GONE);
    }

    @Override
    public void onClick(View v) {
        presenter.sendTouchData(new TouchData(v.getX(),v.getY()));
    }
}
