/*
 *   Copyright 2020-2021 Leon Latsch
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

package dev.leonlatsch.photok.ui.share

import android.app.Application
import androidx.databinding.Bindable
import dev.leonlatsch.photok.BR
import dev.leonlatsch.photok.ui.components.bindings.ObservableViewModel

/**
 * ViewModel for holding information about shared elements.
 *
 * @since 1.2.0
 * @author Leon Latsch
 */
class ReceiveShareViewModel(
    private val app: Application
) : ObservableViewModel(app) {

    @get:Bindable
    var elementsToProcess: Int = 0
        set(value) {
            field = value
            notifyChange(BR.elementsToProcess, value)
        }
}